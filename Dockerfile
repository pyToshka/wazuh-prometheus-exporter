FROM python:3.8-alpine
ENV WAZUH_API_HOST=""
ENV WAZUH_API_PORT=""
ENV WAZUH_API_USERNAME=""
ENV WAZUH_API_PASSWORD=""

COPY . /app
WORKDIR /app

RUN  pip install  --use-deprecated=legacy-resolver --no-cache-dir -r ./requirements.txt \
     && chmod +x ./*.py
EXPOSE 5000
CMD ["./main.py"]
