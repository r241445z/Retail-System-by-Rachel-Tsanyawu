import streamlit as st
import pandas as pd
import pyodbc

# Function to create SQL Server connection
def create_connection():
    connection = pyodbc.connect(
        "DRIVER={ODBC Driver 18 for SQL Server};"
        "SERVER=DESKTOP-A3SK9UM\\SQLEXPRESS;"   # your actual server + instance
        "DATABASE=Retail;"                      # your database
        "Trusted_Connection=yes;"               # Windows Authentication
        "Encrypt=yes;"                          # keep encryption
        "TrustServerCertificate=yes;"           # accept self-signed cert
    )
    return connection


# Streamlit app
st.title("Retail Database Viewer (SQL Server)")

try:
    conn = create_connection()

    # Get all tables in Retail
    query_tables = """
        SELECT TABLE_NAME 
        FROM INFORMATION_SCHEMA.TABLES 
        WHERE TABLE_TYPE='BASE TABLE';
    """
    tables = pd.read_sql(query_tables, conn)["TABLE_NAME"].tolist()

    if tables:
        table_choice = st.selectbox("Select a table:", tables)

        if table_choice:
            # Fetch all data from selected table
            query = f"SELECT * FROM {table_choice};"
            df = pd.read_sql(query, conn)

            st.subheader(f"Data from table: {table_choice}")
            st.dataframe(df, use_container_width=True)

            st.write("**Columns:**", df.columns.tolist())
    else:
        st.warning("No tables found in the Retail database.")

    conn.close()
except Exception as e:
    st.error(f"Error: {e}")
