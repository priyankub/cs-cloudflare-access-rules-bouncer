# Stdlib-only Python: nothing to install, so the image is the base plus one file.
FROM python:3.13-alpine@sha256:2d9aefe2fef018a7eb2c13064c89c71929800fd2e5dccdbf52ea5da5bb8d929a
COPY bouncer.py /app/bouncer.py
USER nobody
ENV PYTHONUNBUFFERED=1
HEALTHCHECK --interval=60s --timeout=10s --start-period=120s CMD ["python", "/app/bouncer.py", "--healthcheck"]
ENTRYPOINT ["python", "/app/bouncer.py"]
