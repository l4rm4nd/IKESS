FROM python:3.13.9-alpine
LABEL Maintainer="LRVT"

COPY ikess.py /app/.

WORKDIR /app
ENTRYPOINT [ "python", "ikess.py"]

CMD [ "python", "ikess.py", "--help"]
