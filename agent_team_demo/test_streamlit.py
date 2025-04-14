import streamlit as st

# Create a simple Streamlit app
st.title("Simple Streamlit Test")
st.write("If you can see this, Streamlit is working correctly!")

# Add a button
if st.button("Click Me"):
    st.success("Button clicked!")

# Display some text
st.markdown("""
## This is a test app
This simple app confirms that Streamlit is installed and working correctly.
Once this works, we can run the full dashboard.
""")

# Show a sidebar
with st.sidebar:
    st.write("Sidebar is working too!")
    name = st.text_input("Enter your name")
    if name:
        st.write(f"Hello, {name}!") 