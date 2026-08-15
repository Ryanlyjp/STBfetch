FROM mcr.microsoft.com/playwright/python:v1.55.0-noble

WORKDIR /app
COPY backend/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY backend/sbeans/ ./sbeans/

ENV PYTHONUNBUFFERED=1
EXPOSE 8085
CMD ["python", "-m", "uvicorn", "sbeans.application:app", "--host", "0.0.0.0", "--port", "8085"]
