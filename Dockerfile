FROM python:3.6

COPY ./requirements.txt /app/requirements.txt
WORKDIR /app
RUN pip install -r requirements.txt

COPY . /app
WORKDIR /app/portcullis

EXPOSE 443
ENTRYPOINT ["gunicorn"]
CMD ["--certfile", "../cert.pem", "--keyfile", "../key.pem", "-w 4", "-b", "0.0.0.0:443", "portcullis:app"]
