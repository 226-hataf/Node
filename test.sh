
docker run -d -e -n test_zeatuh_db POSTGRES_PASSWORD=test_db_123 postgresql:15.1
export POSTGRES_PASSWORD=test_db_123
export POSTGRES_SERVER=localhost
export POSTGRES_DB="zekoder"
coverage run -m pytest  src/test_zeauth/test_groups.py src/test_zeauth/test_roles.py src/test_zeauth/test_users.py
