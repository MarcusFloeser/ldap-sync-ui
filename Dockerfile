FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    SYNC_DATA=/data/jobs.json \
    UI_HOST=0.0.0.0 \
    UI_PORT=5000

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY ldap_sync_ui.py .

RUN useradd --system --no-create-home sync && mkdir /data && chown sync /data
USER sync
VOLUME /data
EXPOSE 5000

CMD ["python", "ldap_sync_ui.py"]
