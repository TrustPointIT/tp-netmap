# TrustPoint Network Map render service
FROM python:3.12-slim

# graphviz binary + DejaVu fonts (for the diagram + confidentiality footer)
RUN apt-get update && apt-get install -y --no-install-recommends \
        graphviz fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY netmap_requirements.txt .
RUN pip install --no-cache-dir -r netmap_requirements.txt
COPY netmap_app.py app.py

# Optional: set RENDER_KEY to require an X-Api-Key header on /render
ENV PORT=8080
EXPOSE 8080
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--workers", "2", "--timeout", "60", "app:app"]
