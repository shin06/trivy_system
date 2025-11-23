# Trivy Scan Visualizer

A Streamlit application to visualize Trivy security scan results.

## Features

- **Upload**: Support for Trivy JSON output files.
- **Dashboard**: Overview of vulnerabilities (Total, Critical, High).
- **Visualization**: Charts showing severity distribution and top vulnerable packages.
- **Filtering**: Filter by severity.
- **Search**: Search by package name, vulnerability ID, or title.

## Prerequisites

- Python 3.8+
- `trivy` (to generate scan reports)

## Installation

1. Clone the repository.
2. Create a virtual environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

1. Run the Streamlit app:
   ```bash
   streamlit run app.py
   ```
2. Open your browser at the URL provided (usually `http://localhost:8501`).
3. Upload a Trivy JSON file.

### Generating a Trivy JSON Report

To generate a report that can be uploaded to this app, run:

```bash
trivy image --format json --output result.json <image-name>
```

## Project Structure

- `app.py`: Main application file.
- `requirements.txt`: Python dependencies.
- `sample_trivy.json`: Sample data for testing.
