def get_product(product_id):
    query = "SELECT * FROM products WHERE id = " + product_id
    return query
