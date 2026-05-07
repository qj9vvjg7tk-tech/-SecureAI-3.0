FROM python:3.11-slim
WORKDIR /app
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY backend/ ./backend/
COPY frontend/ ./frontend/
WORKDIR /app/backend
ENV SECUREAI_DB_PATH=/tmp/secureai.db
CMD uvicorn main:app --host 0.0.0.0 --port $PORT
