"""Threat classification that combines a rule‑based engine and ML models.

This module defines `ThreatClassifier`, a class responsible for assigning
threat labels to incoming HTTP requests.  The classifier operates in two
phases:

1. **Rule‑based phase:**  A set of regular expression signatures derived
   from the OWASP CRS (implemented in `rule_engine.py`) is applied to the
   request.  If any signature matches, the corresponding threat type and
   location are recorded and no machine‑learning prediction is performed.

2. **Machine‑learning phase:**  If no signature matches, a pair of
   scikit‑learn models are used to detect text‑based attacks (SQLi, XSS,
   command injection, path traversal or valid) and parameter‑tampering
   attacks based on the length of parameter values.  The models are loaded
   from ``../Classifier/predictor.joblib`` and ``../Classifier/pt_predictor.joblib``.  If
   the models cannot be loaded a fallback is used that always predicts
   ``'valid'``.
"""

from __future__ import annotations

import json
import urllib.parse
from typing import Dict, Any

import joblib  # scikit‑learn includes joblib

from .request import Request
from .rule_engine import scan_request


class ThreatClassifier:
    """Combines signature matching and machine‑learning for threat detection."""

    def __init__(self) -> None:
        # Attempt to load ML models.  If they are missing fall back to None.
        try:
            self.clf = joblib.load("../Classifier/predictor.joblib")
        except Exception:
            self.clf = None
        try:
            self.pt_clf = joblib.load("../Classifier/pt_predictor.joblib")
        except Exception:
            self.pt_clf = None

    @staticmethod
    def _clean_text(text: str) -> str:
        """Utility function for cleaning and normalising input strings."""
        if text is None:
            return ''
        # unquote repeatedly and collapse whitespace
        prev = text
        for _ in range(5):
            decoded = urllib.parse.unquote_plus(prev)
            if decoded == prev:
                break
            prev = decoded
        return ' '.join(prev.strip().split()).lower()

    @staticmethod
    def _is_valid(parameter: Any) -> bool:
        return parameter is not None and parameter != ''

    def classify_request(self, req: Request) -> None:
        """Populate the request with detected threat labels."""
        if not isinstance(req, Request):
            raise TypeError("Object should be a Request!")

        # First run the rule engine.  If any threats are returned skip ML.
        signature_threats = scan_request(req)
        if signature_threats:
            req.threats = signature_threats
            return

        # Otherwise perform ML classification
        req.threats = {}
        parameters: list = []
        locations: list = []

        # Collect raw features for text classifier
        if self._is_valid(req.request):
            parameters.append(self._clean_text(req.request))
            locations.append('Request')
        if self._is_valid(req.body):
            parameters.append(self._clean_text(req.body))
            locations.append('Body')
        if 'Cookie' in req.headers and self._is_valid(req.headers.get('Cookie')):
            parameters.append(self._clean_text(req.headers['Cookie']))
            locations.append('Cookie')
        if 'User_Agent' in req.headers and self._is_valid(req.headers.get('User_Agent')):
            parameters.append(self._clean_text(req.headers['User_Agent']))
            locations.append('User Agent')
        if 'Accept_Encoding' in req.headers and self._is_valid(req.headers.get('Accept_Encoding')):
            parameters.append(self._clean_text(req.headers['Accept_Encoding']))
            locations.append('Accept Encoding')
        if 'Accept_Language' in req.headers and self._is_valid(req.headers.get('Accept_Language')):
            parameters.append(self._clean_text(req.headers['Accept_Language']))
            locations.append('Accept Language')

        # Text classification
        if parameters and self.clf is not None:
            try:
                predictions = self.clf.predict(parameters)
                for idx, pred in enumerate(predictions):
                    if pred != 'valid':
                        req.threats[pred] = locations[idx]
            except Exception:
                # fall back to no threats if prediction fails
                pass

        # Parameter tampering classification: build length features
        request_parameters: Dict[str, list] = {}
        if self._is_valid(req.request):
            try:
                request_parameters = urllib.parse.parse_qs(self._clean_text(req.request))
            except Exception:
                request_parameters = {}
        body_parameters: Dict[str, Any] = {}
        if self._is_valid(req.body):
            try:
                body_parameters = urllib.parse.parse_qs(self._clean_text(req.body))
            except Exception:
                body_parameters = {}
            if not body_parameters:
                # Fallback to JSON decoding
                try:
                    body_parameters = json.loads(self._clean_text(req.body))
                except Exception:
                    body_parameters = {}

        length_features = []
        locations_len = []
        for vals in request_parameters.values():
            for elem in vals:
                length_features.append([len(elem)])
                locations_len.append('Request')
        for name, value in body_parameters.items():
            if isinstance(value, list):
                for elem in value:
                    length_features.append([len(elem)])
                    locations_len.append('Body')
            else:
                length_features.append([len(value)])
                locations_len.append('Body')

        if length_features and self.pt_clf is not None:
            try:
                pt_preds = self.pt_clf.predict(length_features)
                for idx, pred in enumerate(pt_preds):
                    if pred != 'valid':
                        req.threats[pred] = locations_len[idx]
            except Exception:
                pass

        # If nothing has been flagged mark request as valid
        if not req.threats:
            req.threats['valid'] = ''