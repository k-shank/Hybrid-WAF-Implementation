# ML-based‑WAF – rule based and machine learning

This repository is a rebuilt version of the original
[ML‑based‑WAF by Vladan Stojnić](https://github.com/vladan-stojnic/ML-based-WAF).
It preserves the overall layout of the project while adding a **rule‑based
signature engine** as a first line of defence.  Requests are now processed in
two stages:

1. **Signature engine:** The `rule_engine.py` module contains a set of
   regular expressions derived from the [OWASP ModSecurity Core Rule Set
   (CRS)]【206368457188028†L17-L34】 for common attacks such as SQL injection (sqli), cross‑site
   scripting (xss), command injection (cmdi), and path traversal.  When a
   request is received, its path, body, cookies, and selected headers are
   checked against these patterns.  If any pattern matches, the request is
   classified immediately and no machine‑learning prediction is attempted.

2. **Machine‑learning pipeline:** If no signature triggers, the request is
   forwarded to the existing ML classifier.  The original project relied on
   large pre‑trained models stored in the `Classifier` directory.  In this
   regenerated version those artefacts have been replaced with light‑weight
   placeholders and the code gracefully falls back to predicting “valid” if the
   models are not available.  You can train and drop your own models into
   `Classifier/predictor.joblib` and `Classifier/pt_predictor.joblib` (see the
   Jupyter notebooks in the `Classifier` directory for inspiration).

The WAF can still be run in **sniffing mode** via `python sniffing.py`, and a
simple **REST target** is provided in `rest_app.py`.  A basic **dashboard** for
inspecting logged requests is available through `dashboard.py`.

## Directory structure

* `Classifier` – notebooks and model placeholders for training text and
  parameter‑tampering classifiers.
* `Dataset` – placeholder directory for dataset files.  Large datasets were
  removed from this reproduction to keep the repository light; you can add
  your own data here.
* `WAF` – the core firewall implementation, including
  `sniffing.py`, `request.py`, the new `rule_engine.py` and updated
  `classifier.py` with signature handling.

## Usage

1. Install dependencies (see `requirements.txt`).  The ML classifier
   components require `scikit‑learn`; the dashboard requires `dash` and
   `plotly`.
2. Run the REST test server in one terminal:

   ```bash
   python WAF/rest_app.py
   ```

3. In a separate terminal run the sniffer on the desired port (default 5000):

   ```bash
   sudo python WAF/sniffing.py --port 5000
   ```

4. Use `simple_testing.py` to send some example requests defined in
   `testing_requests.json`.

5. Start the dashboard to inspect the logged requests:

   ```bash
   python WAF/dashboard.py
   ```

## Disclaimer

This project is for educational purposes only.  The rule set provided here
captures only a handful of common patterns and will need extension and
tuning for real‑world use.  Likewise, the ML models shipped in this
repository are placeholders; you should retrain models on realistic data for
production deployments【206368457188028†L17-L34】.