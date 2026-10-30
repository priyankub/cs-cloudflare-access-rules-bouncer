# Stdlib-only Python: nothing to install, so the image is the base plus one file.
FROM python:3.13-alpine@sha256:7984cf56ceaddebe4fefeb75d64000b9f45d8b77b11a09b24524da6cdc3af0c8
COPY bouncer.py /app/bouncer.py
USER nobody
ENV PYTHONUNBUFFERED=1
HEALTHCHECK --interval=60s --timeout=10s --start-period=120s CMD ["python", "/app/bouncer.py", "--healthcheck"]
ENTRYPOINT ["python", "/app/bouncer.py"]
