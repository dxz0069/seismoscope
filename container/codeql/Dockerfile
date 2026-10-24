FROM python:3.12-slim

ARG CODEQL_VERSION=2.26.1
ARG CODEQL_SHA256=15480dda6e20336a9c7ddcb6171e0e9155f1fe73a1d31baeac153821cb89aeab
COPY .build-cache/codeql.zip /tmp/codeql.zip

RUN python -c "import hashlib; p='/tmp/codeql.zip'; actual=hashlib.sha256(open(p,'rb').read()).hexdigest(); assert actual=='${CODEQL_SHA256}', (actual,'${CODEQL_SHA256}')" \
    && python -c "import zipfile; zipfile.ZipFile('/tmp/codeql.zip').extractall('/opt')" \
    && rm /tmp/codeql.zip \
    && chmod -R a+rX /opt/codeql \
    && ln -s /opt/codeql/codeql /usr/local/bin/codeql \
    && python -c "from pathlib import Path; root=Path('/opt/vibe-sec/codeql-suites'); root.mkdir(parents=True); q=Path('/opt/codeql/qlpacks/codeql'); languages={'python':'python','javascript-typescript':'javascript','java-kotlin':'java','go':'go','c-cpp':'cpp','csharp':'csharp','ruby':'ruby','swift':'swift'}; pairs=[(public,pack,kind,list(q.glob(f'{pack}-queries/*/codeql-suites/{pack}-{kind}.qls'))) for public,pack in languages.items() for kind in ('security-extended','security-and-quality')]; missing=[f'{public}:{kind}' for public,pack,kind,matches in pairs if not matches]; assert not missing, 'Missing CodeQL suites: '+','.join(missing); [(root/f'{public}-{kind}.qls').symlink_to(matches[0]) for public,pack,kind,matches in pairs]" \
    && codeql version

LABEL org.opencontainers.image.title="Vibe Sec CodeQL Scanner" \
      org.opencontainers.image.version="${CODEQL_VERSION}" \
      io.vibe-sec.capabilities="codeql-database-analyze"

ENV HOME=/tmp
WORKDIR /workspace
ENTRYPOINT []
