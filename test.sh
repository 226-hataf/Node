
docker run -d -e -n test_zeatuh_db DB_PASSWORD=test_db_123 postgresql:15.1
export DB_PASSWORD=test_db_123
export DB_HOST=localhost
export DB_NAME="zekoder"
coverage run -m pytest  src/test_zeauth/test_groups.py src/test_zeauth/test_roles.py src/test_zeauth/test_users.py
