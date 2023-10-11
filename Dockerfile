# Use an official Python runtime as a parent image
FROM python:3.10-slim

# Set the working directory in the container
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . /app

# Install Poetry and dependencies
RUN pip install --no-cache-dir poetry \
    && poetry config virtualenvs.create false \
    && poetry install

# Make port 80 available to the world outside this container
EXPOSE 80

# Run Uvicorn with reload for development
CMD ["uvicorn", "API.auth:app", "--host", "0.0.0.0", "--port", "80", "--reload"]
