# filepath: /E:/audit-tools/app.py
import streamlit as st
from PyPDF2 import PdfMerger, PdfReader, PdfWriter
import pdfplumber
import pandas as pd
import psycopg2
import hashlib

# Database connection
conn = psycopg2.connect(
    host="ep-billowing-hill-a1dfh4k4-pooler.ap-southeast-1.aws.neon.tech",
    database="audittools",
    user="audittools_owner",
    password="npg_E8c7zPjyWoqQ"
)
cur = conn.cursor()

# Create users table if it doesn't exist
cur.execute('''
    CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY,
        password TEXT NOT NULL
    )
''')
conn.commit()

# Create clients table if it doesn't exist
cur.execute('''
    CREATE TABLE IF NOT EXISTS clients (
        client_id SERIAL PRIMARY KEY,
        client_name TEXT NOT NULL,
        client_code TEXT UNIQUE NOT NULL,
        sector TEXT NOT NULL,
        audit_partner TEXT NOT NULL,
        audit_manager TEXT NOT NULL
    )
''')
conn.commit()

# Function to hash passwords
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Function to check credentials
def check_credentials(username, password):
    cur.execute('SELECT * FROM users WHERE username = %s AND password = %s', (username, hash_password(password)))
    return cur.fetchone() is not None

# Function to register a new user
def register_user(username, password):
    cur.execute('INSERT INTO users (username, password) VALUES (%s, %s)', (username, hash_password(password)))
    conn.commit()

# Function to generate client code
def generate_client_code(client_id):
    return f"B-{client_id:03d}"

# Function to add a new client
def add_client(client_name, sector, audit_partner, audit_manager, client_code):
    cur.execute('INSERT INTO clients (client_name, client_code, sector, audit_partner, audit_manager) VALUES (%s, %s, %s, %s, %s) RETURNING client_id', 
                (client_name, client_code, sector, audit_partner, audit_manager))
    conn.commit()

# Function to get all clients
def get_clients():
    cur.execute('SELECT client_code, client_name, sector, audit_partner, audit_manager FROM clients')
    return cur.fetchall()

# Initialize session state for login
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "username" not in st.session_state:
    st.session_state.username = ""

# Registration form
st.sidebar.title("Register")
new_username = st.sidebar.text_input("New Username", key="register_username")
new_password = st.sidebar.text_input("New Password", type="password", key="register_password")
register_button = st.sidebar.button("Register")

if register_button:
    if new_username and new_password:
        register_user(new_username, new_password)
        st.sidebar.success("User registered successfully!")
    else:
        st.sidebar.error("Please enter a username and password.")

# Login form
if not st.session_state.logged_in:
    st.sidebar.title("Login")
    username = st.sidebar.text_input("Username", key="login_username")
    password = st.sidebar.text_input("Password", type="password", key="login_password")
    login_button = st.sidebar.button("Login")

    if login_button:
        if check_credentials(username, password):
            st.session_state.logged_in = True
            st.session_state.username = username
            st.sidebar.success("Login successful!")
        else:
            st.sidebar.error("Invalid username or password.")

# Logout button
if st.session_state.logged_in:
    if st.sidebar.button("Logout"):
        st.session_state.logged_in = False
        st.session_state.username = ""
        st.experimental_rerun()

# Check login state and show main app if authenticated
if st.session_state.logged_in:
    st.sidebar.success("Logged in as {}".format(st.session_state.username))
    
    st.title("Audit Tools")

    tab1, tab2 = st.tabs([
        "PDF Tools", 
        "Client Database"
    ])

    with tab1:
        st.header("PDF Tools")
        pdf_tool_tabs = st.tabs([
            "PDF Merge Tool", 
            "PDF Split Tool", 
            "PDF to Excel/CSV/Markdown", 
            "PDF Text Extraction", 
            "PDF Metadata Extraction", 
            "PDF Page Rotation", 
            "PDF Encryption/Decryption"
        ])

        with pdf_tool_tabs[0]:
            st.header("PDF Merge Tool")
            uploaded_files = st.file_uploader("Choose PDF files", type="pdf", accept_multiple_files=True, key="merge")

            if st.button("Merge PDFs", key="merge_button"):
                if uploaded_files:
                    merger = PdfMerger()
                    for pdf in uploaded_files:
                        merger.append(pdf)

                    with open("merged.pdf", "wb") as output_file:
                        merger.write(output_file)

                    st.success("PDFs merged successfully!")
                    with open("merged.pdf", "rb") as file:
                        st.download_button("Download Merged PDF", file, file_name="merged.pdf")
                else:
                    st.error("Please upload at least two PDF files to merge.")

        with pdf_tool_tabs[1]:
            st.header("PDF Split Tool")
            uploaded_file = st.file_uploader("Choose a PDF file", type="pdf", key="split")

            if uploaded_file:
                reader = PdfReader(uploaded_file)
                num_pages = len(reader.pages)
                st.write(f"The selected PDF has {num_pages} pages.")

                start_page = st.number_input("Start Page", min_value=1, max_value=num_pages, value=1, key="split_start_page")
                end_page = st.number_input("End Page", min_value=1, max_value=num_pages, value=num_pages, key="split_end_page")

                if st.button("Split PDF", key="split_button"):
                    if start_page <= end_page:
                        writer = PdfWriter()
                        for i in range(start_page - 1, end_page):
                            writer.add_page(reader.pages[i])

                        with open("split.pdf", "wb") as output_file:
                            writer.write(output_file)

                        st.success("PDF split successfully!")
                        with open("split.pdf", "rb") as file:
                            st.download_button("Download Split PDF", file, file_name="split.pdf")
                    else:
                        st.error("End page must be greater than or equal to start page.")

        with pdf_tool_tabs[2]:
            st.header("PDF to Excel/CSV/Markdown")
            uploaded_file = st.file_uploader("Choose a PDF file", type="pdf", key="convert")

            if uploaded_file:
                with pdfplumber.open(uploaded_file) as pdf:
                    all_tables = []
                    for page in pdf.pages:
                        tables = page.extract_tables()
                        for table in tables:
                            all_tables.append(table)

                    if all_tables:
                        st.write("Extracted Tables:")
                        for i, table in enumerate(all_tables):
                            df = pd.DataFrame(table[1:], columns=table[0])
                            st.write(f"Table {i+1}")
                            st.dataframe(df)

                            # Download options
                            csv = df.to_csv(index=False).encode('utf-8')
                            excel = df.to_excel(index=False).encode('utf-8')
                            markdown = df.to_markdown(index=False).encode('utf-8')

                            st.download_button(
                                label="Download as CSV",
                                data=csv,
                                file_name=f"table_{i+1}.csv",
                                mime="text/csv",
                            )

                            st.download_button(
                                label="Download as Excel",
                                data=excel,
                                file_name=f"table_{i+1}.xlsx",
                                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                            )

                            st.download_button(
                                label="Download as Markdown",
                                data=markdown,
                                file_name=f"table_{i+1}.md",
                                mime="text/markdown",
                            )
                    else:
                        st.error("No tables found in the PDF.")

        with pdf_tool_tabs[3]:
            st.header("PDF Text Extraction")
            uploaded_file = st.file_uploader("Choose a PDF file", type="pdf", key="text_extract")

            if uploaded_file:
                with pdfplumber.open(uploaded_file) as pdf:
                    all_text = ""
                    for page in pdf.pages:
                        all_text += page.extract_text() + "\n"

                    st.text_area("Extracted Text", all_text, height=300, key="extracted_text")

                    # Download option
                    st.download_button(
                        label="Download Extracted Text",
                        data=all_text,
                        file_name="extracted_text.txt",
                        mime="text/plain",
                    )

        with pdf_tool_tabs[4]:
            st.header("PDF Metadata Extraction")
            uploaded_file = st.file_uploader("Choose a PDF file", type="pdf", key="metadata_extract")

            if uploaded_file:
                reader = PdfReader(uploaded_file)
                metadata = reader.metadata
                st.write("Metadata:", metadata)

        with pdf_tool_tabs[5]:
            st.header("PDF Page Rotation")
            uploaded_file = st.file_uploader("Choose a PDF file", type="pdf", key="rotate")

            if uploaded_file:
                reader = PdfReader(uploaded_file)
                num_pages = len(reader.pages)
                st.write(f"The selected PDF has {num_pages} pages.")

                page_number = st.number_input("Page Number", min_value=1, max_value=num_pages, value=1, key="rotate_page_number")
                rotation_angle = st.selectbox("Rotation Angle", [90, 180, 270], key="rotate_angle")

                if st.button("Rotate Page", key="rotate_button"):
                    writer = PdfWriter()
                    for i in range(num_pages):
                        page = reader.pages[i]
                        if i == page_number - 1:
                            page.rotate_clockwise(rotation_angle)
                        writer.add_page(page)

                    with open("rotated.pdf", "wb") as output_file:
                        writer.write(output_file)

                    st.success("Page rotated successfully!")
                    with open("rotated.pdf", "rb") as file:
                        st.download_button("Download Rotated PDF", file, file_name="rotated.pdf")

        with pdf_tool_tabs[6]:
            st.header("PDF Encryption/Decryption")
            uploaded_file = st.file_uploader("Choose a PDF file", type="pdf", key="encrypt_decrypt")

            password = st.text_input("Password", type="password", key="encrypt_decrypt_password")

            if st.button("Encrypt PDF", key="encrypt_button"):
                if uploaded_file and password:
                    reader = PdfReader(uploaded_file)
                    writer = PdfWriter()

                    for page in reader.pages:
                        writer.add_page(page)

                    writer.encrypt(password)

                    with open("encrypted.pdf", "wb") as output_file:
                        writer.write(output_file)

                    st.success("PDF encrypted successfully!")
                    with open("encrypted.pdf", "rb") as file:
                        st.download_button("Download Encrypted PDF", file, file_name="encrypted.pdf")

            if st.button("Decrypt PDF", key="decrypt_button"):
                if uploaded_file and password:
                    reader = PdfReader(uploaded_file)
                    if reader.is_encrypted:
                        reader.decrypt(password)

                    writer = PdfWriter()
                    for page in reader.pages:
                        writer.add_page(page)

                    with open("decrypted.pdf", "wb") as output_file:
                        writer.write(output_file)

                    st.success("PDF decrypted successfully!")
                    with open("decrypted.pdf", "rb") as file:
                        st.download_button("Download Decrypted PDF", file, file_name="decrypted.pdf")

    with tab2:
        st.header("Client Database")

        # Initialize session state for client form
        if "client_name" not in st.session_state:
            st.session_state.client_name = ""
        if "sector" not in st.session_state:
            st.session_state.sector = ""
        if "audit_partner" not in st.session_state:
            st.session_state.audit_partner = ""
        if "audit_manager" not in st.session_state:
            st.session_state.audit_manager = ""

        # Client registration form
        client_name = st.text_input("Client Name", key="client_name", value=st.session_state.client_name)
        sector = st.text_input("Sector", key="sector", value=st.session_state.sector)
        audit_partner = st.text_input("Audit Partner", key="audit_partner", value=st.session_state.audit_partner)
        audit_manager = st.text_input("Audit Manager", key="audit_manager", value=st.session_state.audit_manager)
        add_client_button = st.button("Add Client")

        if add_client_button:
            if client_name and sector and audit_partner and audit_manager:
                # Generate client code
                cur.execute('SELECT MAX(client_id) FROM clients')
                max_client_id = cur.fetchone()[0]
                if max_client_id is None:
                    max_client_id = 0
                client_code = generate_client_code(max_client_id + 1)
                
                # Add client with client code
                add_client(client_name, sector, audit_partner, audit_manager, client_code)
                st.success("Client added successfully!")
                # Clear the form fields
                st.session_state.client_name = ""
                st.session_state.sector = ""
                st.session_state.audit_partner = ""
                st.session_state.audit_manager = ""
            else:
                st.error("Please fill in all fields.")

        # Display all clients
        st.subheader("All Clients")
        clients = get_clients()
        df_clients = pd.DataFrame(clients, columns=["Client Code", "Client Name", "Sector", "Audit Partner", "Audit Manager"])
        st.dataframe(df_clients)
else:
    st.sidebar.error("Invalid username or password.")