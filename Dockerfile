FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    SYNC_DATA=/data/jobs.json \
    UI_HOST=0.0.0.0 \
    UI_PORT=5000

# tzdata: damit Cron-Zeitplaene in der per TZ gesetzten Zeitzone laufen
RUN apt-get update \
    && apt-get install -y --no-install-recommends tzdata \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY ldap_sync_ui.py entrypoint.sh ./
COPY templates templates
COPY static static

# "sync" existiert im Debian-Basisimage bereits, daher eigener Benutzername
RUN useradd --system --no-create-home ldapsync \
    && mkdir /data && chown ldapsync:ldapsync /data \
    && chmod +x entrypoint.sh

VOLUME /data
EXPOSE 5000

# Startet als root, korrigiert /data und wechselt dann zu "ldapsync"
ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["python", "ldap_sync_ui.py"]
