FROM python:3.12-slim
WORKDIR /srv
RUN useradd -r -u 10001 prismcip
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
COPY scripts ./scripts
ENV PRISMCIP_DATA_DIR=/data
RUN mkdir -p /data && chown prismcip /data
USER prismcip
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips=*"]
