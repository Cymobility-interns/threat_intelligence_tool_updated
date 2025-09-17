# dbapp/check_db.py
from sqlalchemy import inspect
from dbapp.database import engine

def list_tables_and_columns():
    inspector = inspect(engine)

    print("Tables in database:")
    for table_name in inspector.get_table_names():
        print(f" - {table_name}")
        columns = inspector.get_columns(table_name)
        for col in columns:
            print(f"    {col['name']} ({col['type']})")

if __name__ == "__main__":
    list_tables_and_columns()
