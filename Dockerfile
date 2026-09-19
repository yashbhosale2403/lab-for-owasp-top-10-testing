FROM python:3.14-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# DjangoGoat only needs Django itself to run (pytest/pytest-django are for
# tests) -- it deliberately has no scanner-related dependencies.
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

RUN python manage.py migrate --noinput && python manage.py seed_lab_data

EXPOSE 9000

CMD ["python", "manage.py", "runserver", "0.0.0.0:9000"]
