import pandas as pd
import pydot

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.externals import joblib
from sklearn.tree import export_graphviz

import os
os.environ["PATH"] += os.pathsep + "C:\\Program Files (x86)\\Graphviz2.38\\bin"


def return_nonstring_col(columns):
    cols_to_keep = []
    train_cols = []
    for column in columns:
        if column != 'url' and column != 'host' and column != 'path':
            cols_to_keep.append(column)
            if column != 'label':
                train_cols.append(column)
    return [cols_to_keep, train_cols]


if __name__ == '__main__':
    csv = pd.read_csv('C:\\Users\\Nilesh Shaikh\\Desktop\\Peerlox\\feature_set\\mal_url.csv')
    cols_to_keep, train_cols = return_nonstring_col(csv.columns)
    train_x, test_x, train_y, test_y = train_test_split(csv[train_cols], csv['label'], train_size=0.8, random_state=42)
    trained_model = RandomForestClassifier(n_estimators=15)
    trained_model.fit(train_x, train_y)
    predictions = trained_model.predict(test_x)

    count = 1
    for tree in trained_model.estimators_:
        export_graphviz(tree, out_file='tree.dot')
        (graph,) = pydot.graph_from_dot_file('tree.dot')
        graph.write_png("C:\\Users\\Nilesh Shaikh\\Desktop\\Peerlox\\tree\\"+str(count)+'tree.png')
        count += 1

    print("Train Accuracy :: ", accuracy_score(train_y, trained_model.predict(train_x)) * 100)
    print("Test Accuracy  :: ", accuracy_score(test_y, predictions) * 100)
    print("Confusion matrix\n ", confusion_matrix(test_y, predictions))

    joblib.dump(trained_model, 'C:\\Users\\Nilesh Shaikh\\Desktop\\Peerlox\\ml_models\\ml_url.pkl')
