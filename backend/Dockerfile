# Use an official Python runtime as a parent image
FROM python:3.12-slim

# Set the working directory in the container
WORKDIR /app

# Copy the backend requirements file
COPY backend/requirements.txt ./backend/

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt

# Copy the frontend and backend folders
COPY backend/ ./backend/
COPY frontend/ ./frontend/

# Ensure the uploads directory exists
RUN mkdir -p backend/uploads

# Expose the port the app runs on
EXPOSE 5000

# Set working directory to backend where app.py lives
WORKDIR /app/backend

# Command to run the Flask application
CMD ["python", "app.py"]
