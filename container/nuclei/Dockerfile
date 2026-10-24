FROM python:3.12-slim

ARG NUCLEI_VERSION=3.11.0
ARG NUCLEI_SHA256=dc238d6040813e14fc30514dac5a2eb1b430c694f3ca99eee2a5097e55076283
COPY .build-cache/nuclei.zip /tmp/nuclei.zip

RUN python -c "import hashlib; p='/tmp/nuclei.zip'; actual=hashlib.sha256(open(p,'rb').read()).hexdigest(); assert actual=='${NUCLEI_SHA256}', (actual,'${NUCLEI_SHA256}')" \
    && python -c "import zipfile; z=zipfile.ZipFile('/tmp/nuclei.zip'); open('/usr/local/bin/nuclei','wb').write(z.read('nuclei'))" \
    && rm /tmp/nuclei.zip \
    && chmod 0755 /usr/local/bin/nuclei

COPY templates /opt/vibe-sec/nuclei

LABEL org.opencontainers.image.title="Vibe Sec Nuclei Scanner" \
      org.opencontainers.image.version="${NUCLEI_VERSION}" \
      io.vibe-sec.capabilities="nuclei-curated-http"

ENV HOME=/tmp
WORKDIR /workspace
ENTRYPOINT []
