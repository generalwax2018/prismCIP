# Third-party code

PrismCIP depends on FastAPI, Starlette, SQLAlchemy, Jinja2, itsdangerous, python-multipart and Uvicorn (see
`requirements.txt`). One file is copied in from another project:

| File | Project | License |
|---|---|---|
| `app/qrcodegen.py` | [QR Code generator library](https://www.nayuki.io/page/qr-code-generator-library), Project Nayuki | MIT (notice kept at the top of the file) |

It draws the QR code on the two-step sign-in setup page, so authenticator apps can be added without sending the
secret to an outside service.
