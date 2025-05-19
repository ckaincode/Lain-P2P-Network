PYTHON=python3


setup: 
	pip install -r requirements.txt

server:
	python3 run_tracker.py

peer:
	python3 run_client.py

clean:
	find . -name '*.pyc' -delete
	find . -name '__pycache__' -type d -exec rm -r {} +