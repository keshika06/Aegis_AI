FROM python:3.12-slim

WORKDIR /app

RUN pip install --no-cache-dir "fastapi>=0.110" "uvicorn>=0.27" "httpx>=0.27" "pydantic>=2.7"

COPY app.py .

EXPOSE 8003

# No host paths baked in: everything that varies comes from the environment.
CMD ["python", "-m", "uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8003"]
