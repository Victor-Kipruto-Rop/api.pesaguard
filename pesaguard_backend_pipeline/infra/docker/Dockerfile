FROM python:3.12-slim
WORKDIR /app
COPY pesaguard_backend_pipeline/requirements_3.txt ./requirements_3.txt
RUN pip install --no-cache-dir -r requirements_3.txt
COPY . .
RUN mkdir -p /tmp/pesaguard-prometheus \
	&& sed -i 's/\r$//' pesaguard_backend_pipeline/worker_entrypoint.sh
CMD ["python", "-m", "pesaguard_backend_pipeline.canonical_app"]
