FROM python:3.12.3-bookworm
WORKDIR /opt/ads/
COPY . .
RUN pip install -r requirements.txt
