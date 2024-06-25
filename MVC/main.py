from controllers.controller import Controller
from models.model import Model

if __name__ == "__main__":
    model = Model()
    app = Controller(model)
    app.view.start()