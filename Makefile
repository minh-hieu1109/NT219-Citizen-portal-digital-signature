.PHONY: up down logs check migrate test create-demo-users web-smoke demo-remote demo-client-pkcs11 demo-tamper demo-revoke demo-replay demo-ocsp-unavailable demo-cms benchmark

up:
	docker compose up -d --build

down:
	docker compose down

logs:
	docker compose logs web --tail=100

check:
	docker compose exec web python manage.py check

dry-migrations:
	docker compose exec web python manage.py makemigrations --check --dry-run

migrate:
	docker compose exec web python manage.py migrate

test:
	docker compose exec web python manage.py test

create-demo-users:
	docker compose exec web python manage.py create_demo_users

web-smoke:
	docker compose exec web python manage.py web_smoke_check

demo-remote:
	docker compose exec web python experiments/01_end_to_end_remote_sign.py

demo-client-pkcs11:
	docker compose exec web python experiments/02_end_to_end_client_pkcs11_sign.py

demo-tamper:
	docker compose exec web python experiments/03_tamper_document_after_sign.py

demo-revoke:
	docker compose exec web python experiments/04_revoke_certificate_and_verify.py

demo-replay:
	docker compose exec web python experiments/05_replay_remote_signing_request.py

demo-ocsp-unavailable:
	docker compose exec web python experiments/07_ocsp_unavailable.py

demo-cms:
	docker compose exec web python experiments/09_cms_pkcs7_detached_signature.py

benchmark:
	docker compose exec web python experiments/08_benchmark_sign_verify.py
