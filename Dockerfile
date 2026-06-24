# Playwright's official Python image ships Chromium + all system libraries already,
# so visual-clone detection works regardless of the host OS — this also sidesteps the
# "Playwright does not support chromium on ubuntu26.04" problem on newer hosts.
# Pin the tag to the Playwright version your requirements resolve to.
FROM mcr.microsoft.com/playwright/python:v1.49.1-jammy

WORKDIR /app

# Install Python deps first for better layer caching.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# App code.
COPY domainhunter.py realtime_monitor.py ./

# Runtime data (config, monitored list, workbooks, state) lives in /data so it can be
# mounted as a volume and survive container rebuilds.
ENV DOMAINHUNTER_BROWSER_NO_SANDBOX=1
WORKDIR /data
VOLUME ["/data"]

# Default to the real-time monitor; override `command:` in compose for a batch scan.
ENTRYPOINT ["python"]
CMD ["/app/realtime_monitor.py"]
