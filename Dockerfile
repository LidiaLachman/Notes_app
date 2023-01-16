FROM python:3.8-alpine
WORKDIR /home
RUN apk upgrade --update
RUN apk add --no-cache gcc musl-dev linux-headers libffi-dev
COPY requirements.txt .
RUN python3 -m pip install -r requirements.txt
COPY __run__.py .
COPY app.py .
COPY forms.py .
COPY models.py .
COPY routes.py .
COPY instance ./instance
COPY cert ./cert
COPY templates ./templates
CMD [ "python3", "app.py" ]
