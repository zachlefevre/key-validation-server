# Configuration
port = 8888
# How to run
Nothing special here!

`cargo run` will start the server.

You will now have a server running on `localhost:8888`

# API
- `/verify` accepts a multipart file upload of a binary encoded key and a binary encoded signed file
- `/nonce` accepts a multipart file upload of a key and produces a nonce

# Example
``` sh
curl 'localhost:8888/nonce' --form "key=@$HOME/one.key" > $HOME/one_key_nonce
gpg --output $HOME/signed_one_key_nonce --sign one_key_nonce
curl -i 'localhost:8888/verify' --form "key=@$HOME/one.key" --form "signed=@$HOME/signed_one_key_nonce"
```

Additional examples can be foundin bin/holder

# Testing
- Generate keys with ids `interview_test` and `other_interview_test`
- Start the server with `cargo run`
- Evaluate holder script (`./bin/holder`) to see a run through of a successful key validation and a handful of successful key validation rejections.
