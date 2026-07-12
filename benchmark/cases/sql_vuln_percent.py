def get_order(order_id):
    query = "SELECT * FROM orders WHERE id = %s" % order_id
    return query
