import sys
import os
import pandas as pd

def main():
    slist = 'slists.txt'
    if not os.path.exists(slist):
        print("The file %s does not exist."%slist)
        sys.exit()
    list_csv = load_list(slist)
    print(list_csv)
    run(list_csv)

def run(list_csv):
    list_pd = []
    for csvfile in list_csv:
        tmp = pd.read_csv(csvfile, sep=',', index_col=False)
        if tmp is not None and len(tmp) > 0:
            list_pd.append(tmp)
    pd_cat = pd.concat(list_pd)
    print(pd_cat.head())
    print("data points: %d" %len(pd_cat))
    pd_cat = pd_cat[pd_cat.data_type!='omit']
    pd_cat = pd_cat[pd_cat.entropy>0]
    pd_cat = pd_cat.loc[:, ['data_proto', 'data_type', 'entropy']]

    avg = pd_cat.groupby(['data_type', 'data_proto']).mean().reset_index()
    avg.columns = ['data_type', 'data_proto', 'avg']
    std = pd_cat.groupby(['data_type', 'data_proto']).std().reset_index()
    std.columns = ['data_type', 'data_proto', 'std']

    mi = pd_cat.groupby(['data_type', 'data_proto']).min().reset_index()
    mi.columns = ['data_type', 'data_proto', 'mi']
    ma = pd_cat.groupby(['data_type', 'data_proto']).max().reset_index()
    ma.columns = ['data_type', 'data_proto', 'ma']

    final = avg.merge(std)
    final = final.merge(mi)
    final = final.merge(ma)
    print(final)

    # print('\n\nMean')
    # print(pd_cat.groupby(['data_type', 'data_proto']).mean())
    # print('\n\nStandard deviation')
    # print(pd_cat.groupby(['data_type', 'data_proto']).std())
    #
    # print('\n\nMin ')
    # print(pd_cat.groupby(['data_type', 'data_proto']).min())
    #
    # print('\n\nMax ')
    # print(pd_cat.groupby(['data_type', 'data_proto']).max())

def load_list(fn, col_index=0, comment='#', split_char='\t', allow_repeat=False):
    l = []
    if not os.path.exists(fn):
        print('%s not' % fn)
        return l
    with open(fn) as ff:
        for line in ff.readlines():
            line = line.strip()
            if line == '' or line.startswith(comment):
                continue
            cols = line.split(split_char)
            if len(cols) < col_index+1:
                continue
            if allow_repeat:
                l.append(cols[col_index])
            else:
                if cols[col_index] not in l:
                    l.append(cols[col_index])
    return l

if __name__ == '__main__':
    main()
