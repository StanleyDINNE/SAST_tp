from flask import Flask, request

app = Flask(__name__)

@app.route('/')
def index():
	return '''
<html>
<body>
	<form action="/transfer" method="POST">
		<input type="text" name="amount" />
		<input type="text" name="receiver" />
		<input type="submit" value="Transfer" />
	</form>
</body>
</html>
'''

@app.route('/transfer', methods=['POST'])
def transfer():

	amount = request.form['amount']
	# Sanitizing the amount
	if not amount.isdigit():
		return 'Error in the amount given'

	receiver_account = request.form['receiver']
	# Sanitizing the receiver name
	if not (receiver_account.translate({
		ord('_'): '', ord(' '): '', ord('-'): '', ord('.'): ''
	}).isalpha()):
		return 'Error in the receiver account name'

	return f'''{amount} transférés vers {receiver_account}'''

if __name__ == '__main__':
	app.run()
