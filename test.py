import cryptnox_sdk_py
from cryptnox_sdk_py import exceptions

def is_connection_open(connection):
    """Check if the connection is open."""
    if connection is None:
        return False
    if not hasattr(connection, '_reader') or connection._reader is None:
        return False
    if not hasattr(connection._reader, '_connection') or connection._reader._connection is None:
        return False
    return True

connection = None
try:
    # Connect to the Cryptnox card first
    connection = cryptnox_sdk_py.Connection(0)  # Connect to card at index 0
    card = cryptnox_sdk_py.factory.get_card(connection)
    
    # Once connected, verify the PIN
    pin_to_test = "000000000"  # Example PIN
    card.verify_pin(pin_to_test)
    print("PIN verified successfully. Card is ready for operations.")
except exceptions.ReaderException:
    print("Reader not found at index")
except exceptions.PinException:
    print("Invalid PIN code.")
except exceptions.DataValidationException:
    print("Invalid PIN length or PIN authentication disabled.")
except exceptions.SoftLock:
    print("Card is locked. Please power cycle the card.")
except exceptions.CryptnoxException as error:
    print(f"Error loading card: {error}")
finally:
    # Always close the connection when done
    if connection:
        print(f"\nBefore disconnect:")
        print(f"  Connection object: {connection}")
        print(f"  Connection is open: {is_connection_open(connection)}")
        
        connection.disconnect()
        
        print(f"\nAfter disconnect:")
        print(f"  Connection object: {connection}")
        print(f"  Connection is open: {is_connection_open(connection)}")
        print(f"  Connection closed successfully: {not is_connection_open(connection)}")