FROM python:3.12

WORKDIR /app

COPY app.py /app/
COPY templates /app/templates/
COPY requirements.txt /app/
COPY database.py /app/
COPY static /app/static/
COPY blog.db /app/

RUN pip install -r requirements.txt

EXPOSE 5000

CMD ["python", "app.py"]