class Tracker(object):
    def __init__(self):
        pass


class Record(object):
    def __init__(self):
        pass


class Questions(object):
    def __init__(self):
        self.questions = {}


class Question(object):
    def __init__(self, question):
        self.question = question

    def addQuestion(self, packet, question):
        pass


class Answers(object):
    def __init__(self):
        self.answers = {}

    def addAnswer(self, packet, answer):
        pass


class Answer(object):
    def __init__(self, answer):
        self.answer = answer

