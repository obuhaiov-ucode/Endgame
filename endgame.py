import json
import argparse
import pprint
import re
import sys
import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
import yaml
import logging
from tkinter import *
from history import *
from endgame_requests import request_method

logger = logging.getLogger()

if not logger.hasHandlers():
    handler = logging.FileHandler('log.txt')
    formatter = logging.Formatter('%(levelname)s %(message)s')

    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

def insert_all(tree, id_p, node):
    i = 0
    for item in node:
        if isinstance(item, dict) and isinstance(node, list):
            "List_of_dicts"
            id = tree.insert(id_p, 'end', text=str(i) + ': {' + str(len(item.values())) + '}')
            insert_all(tree, id, item)
        elif not isinstance(item, (dict, list)) and isinstance(node, list):
            "List"
            if isinstance(item, str):
                tree.insert(id_p, 'end', text=f'{str(i)}: "{item}"')
            else:
                tree.insert(id_p, 'end', text=f'{str(i)}: {item}')
        elif isinstance(item, str) and isinstance(node[item], list):
            "Dict_of_lists"
            id = tree.insert(id_p, 'end', text=item + ': [' + str(len(node[item])) + ']')
            insert_all(tree, id, node[item])
        elif isinstance(item, str) and isinstance(node, dict) \
                and isinstance(node.get(item), dict):
            "Dict_of_named_dicts"
            id = tree.insert(id_p, 'end', text=item + ': {' + str(len(node.get(item))) + '}')
            insert_all(tree, id, node.get(item))
        elif isinstance(item, str) and not isinstance(node.get(item), (dict, list)) \
                and isinstance(node, dict):
            "Scalar"
            if isinstance(node.get(item), str):
                tmp = f'{item}: "{node.get(item)}"'
            else:
                tmp = f'{item}: {node.get(item)}'
            tree.insert(id_p, 'end', text=tmp)
        else:
            "Empty_value"
            if isinstance(item, str):
                tree.insert(id_p, 'end', text=f'{str(i)}: "{item}"')
            else:
                tree.insert(id_p, 'end', text=f'{str(i)}: {item}')
        i += 1
    pass

def tree(valid_data, filename):
    def change_yaml():
        tree_window.destroy()
        run_yaml(valid_data)

    def change_raw():
        tree_window.destroy()
        run_raw(valid_data)


    def change_pretty():
        tree_window.destroy()
        run_pretty(valid_data)

    tree_window = Tk()
    tree_window.title(f"Tree View")
    menu = tk.Menu(tree_window)
    tree_window.config(menu=menu)

    menu.add_command(label="Raw view", font=("Times New Roman", 12, "italic"), command=change_raw)
    menu.add_command(label="Pretty view", font=("Times New Roman", 12, "italic"), command=change_pretty)
    menu.add_command(label="Yaml view", font=("Times New Roman", 12, "italic"), command=change_yaml)

    if valid_data.get("Time"):
        time = valid_data.pop("Time")
        status = "OK"
        if valid_data.get('Status') > 400:
            status = "Not OK"
        fr = tk.LabelFrame(tree_window, bd=3, text=f"Got response {valid_data.get('Status')} {status} in {time} seconds",
                       labelanchor=tk.N, font=("Times New Roman", 14, "italic"))
        fr.grid(row=0, column=0, sticky="nsew")
        if status == "OK":
            fr.config(bg="#cadaba")

        tree = ttk.Treeview(fr)
        tree_window.geometry("810x265")
    else:
        tree = ttk.Treeview(tree_window)
        tree_window.geometry("800x235")
    tree.column("#0", minwidth=0, width=785)
    tree.heading("#0", text=filename, anchor=tk.W)
    ysb = ttk.Scrollbar(tree_window, orient=tk.VERTICAL,
                        command=tree.yview)
    xsb = ttk.Scrollbar(tree_window, orient=tk.HORIZONTAL,
                        command=tree.xview)
    tree.configure(yscroll=ysb.set, xscroll=xsb.set)

    tree.grid(row=0, column=0, sticky=tk.N + tk.S + tk.E + tk.W)
    ysb.grid(row=0, column=1, sticky=tk.N + tk.S)
    xsb.grid(row=1, column=0, sticky=tk.E + tk.W)
    tree.rowconfigure(0, weight=1)
    tree.columnconfigure(0, weight=1)

    if isinstance(valid_data, list):
        id = tree.insert('', 'end', text='[' + str(len(valid_data)) + ']')
    else:
        id = tree.insert('', 'end', text='{' + str(len(valid_data)) + '}')
    insert_all(tree, id, valid_data)

    tree_window.mainloop()

def create_text(data, fr):
    text = tk.Text(fr, wrap=tk.WORD, font=font12)
    text.insert(1.0, data)
    text.grid(row=0, column=0, sticky="nsew")
    scroll = tk.Scrollbar(fr, command=text.yview)
    text.config(yscrollcommand=scroll.set)
    scroll.grid(row=0, column=1, sticky="nsew")

def run_raw(data):
    def change_tree():
        raw_window.destroy()
        if not data.get('URL'):
            tree(data, '')
        else:
            tree(data, data.get('URL'))

    def change_pretty():
        raw_window.destroy()
        run_pretty(data)

    def change_yaml():
        raw_window.destroy()
        run_yaml(data)

    raw_window = tk.Tk()
    raw_window.title(f"Raw view of {data.get('URL')}")
    menu = tk.Menu(raw_window)
    raw_window.config(menu=menu)

    menu.add_command(label="Tree view", font=font12i, command=change_tree)
    menu.add_command(label="Pretty view", font=font12i, command=change_pretty)
    menu.add_command(label="Yaml view", font=font12i, command=change_yaml)

    if data.get("Time"):
        time = data.pop("Time")
        status = "OK"
        if data.get('Status') > 400:
            status = "Not OK"

        fr = tk.LabelFrame(raw_window, bd=2, text=f"Got response {data.get('Status')} {status}"
                                                  f" in {time} seconds", labelanchor=tk.N,
                           font=("Times New Roman", 14, "italic"))
        fr.grid(row=0, column=0, sticky="nsew")
        create_text(data, fr)
        if status == "OK":
            fr.config(bg="#cadaba")
    else:
       create_text(data, raw_window)

def run_pretty(data):
    def change_tree():
        pretty_window.destroy()
        if not data.get('URL'):
            tree(data, '')
        else:
            tree(data, data.get('URL'))

    def change_raw():
        pretty_window.destroy()
        run_raw(data)


    def change_yaml():
        pretty_window.destroy()
        run_yaml(data)

    pretty_window = tk.Tk()
    pretty_window.title(f"Pretty view of {data.get('URL')}")
    menu = tk.Menu(pretty_window)
    pretty_window.config(menu=menu)

    menu.add_command(label="Tree view", font=font12i, command=change_tree)
    menu.add_command(label="Raw view", font=font12i, command=change_raw)
    menu.add_command(label="Yaml view", font=font12i, command=change_yaml)

    if data.get("Time"):
        time = data.pop("Time")
        status = "OK"
        if data.get('Status') > 400:
            status = "Not OK"

        fr = tk.LabelFrame(pretty_window, bd=2, text=f"Got response {data.get('Status')} {status} in {time} seconds",
                       labelanchor=tk.N, font=("Times New Roman", 14, "italic"))
        fr.grid(row=0, column=0, sticky="nsew")
        create_text(pprint.pformat(data, sort_dicts=False), fr)
        if status == "OK":
            fr.config(bg="#cadaba")
    else:
        create_text(pprint.pformat(data, sort_dicts=False), pretty_window)

def run_yaml(data):
    def change_tree():
        yaml_window.destroy()
        if not data.get('URL'):
            tree(data, '')
        else:
            tree(data, data.get('URL'))


    def change_raw():
        yaml_window.destroy()
        run_raw(data)


    def change_pretty():
        yaml_window.destroy()
        run_pretty(data)

    yaml_window = tk.Tk()
    yaml_window.title(f"Yaml view of {data.get('URL')}")
    menu = tk.Menu(yaml_window)
    yaml_window.config(menu=menu)

    menu.add_command(label="Tree view", font=font12i, command=change_tree)
    menu.add_command(label="Raw view", font=font12i, command=change_raw)
    menu.add_command(label="Pretty view", font=font12i, command=change_pretty)

    if data.get("Time"):
        time = data.pop("Time")
        status = "OK"
        if data.get('Status') > 400:
            status = "Not OK"
        fr = tk.LabelFrame(yaml_window, bd=2, text=f"Got response {data.get('Status')} {status} in {time} seconds",
                       labelanchor=tk.N, font=("Times New Roman", 14, "italic"))
        fr.grid(row=0, column=0, sticky="nsew")
        create_text(yaml.safe_dump(data, sort_keys=False), fr)
        if status == "OK":
            fr.config(bg="#cadaba")
    else:
        create_text(yaml.safe_dump(data, sort_keys=False), yaml_window)

def set_view():
    if val == 0:
        cur_view = "Tree View"
    elif val == 1:
        cur_view = "Raw View"
    elif val == 2:
        cur_view = "Pretty View"
    elif val == 3:
        cur_view = "Yaml View"

def show_view(data):
    val = cur_view.get()
    if data:
        if val == 0:
            tree(data, data.get('URL'))
        elif val == 1:
            run_raw(data)
        elif val == 2:
            run_pretty(data)
        elif val == 3:
            run_yaml(data)

def set_log_debug():
    logger.setLevel(logging.DEBUG)
    cur_log.set(10)

def set_log_info():
    logger.setLevel(logging.INFO)
    cur_log.set(20)

def set_log_warn():
    logger.setLevel(logging.WARNING)
    cur_log.set(30)

def get_variables():
    with open("variables.yaml", 'r') as f:
        try:
            return yaml.safe_load(f)
        except:
            return {}

def show_help():
    help_window = tk.Tk()
    help_window.title(f"Help")

    text = tk.Text(help_window, wrap=tk.WORD, font=font12)
    text.insert(1.0, f"API allows to work with html requests GET, POST, PUT, PATCH, DELETE "
     "and visualize the data of the request and response in few convenient formats. "
    "\nSee readme for more info.")
    text.grid(row=0, column=0, sticky="nsew")

class ScrollableFrame(ttk.Frame):
    def __init__(self, container, *args, **kwargs):
        super().__init__(container, *args, **kwargs)
        canvas = tk.Canvas(self)
        scrollbar = ttk.Scrollbar(self, orient="vertical", command=canvas.yview)
        self.scrollable_frame = ttk.Frame(canvas, height=800)

        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(
                scrollregion=canvas.bbox("all")
            )
        )

        canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

def show_history(cond=None, sort=None):
    def show_success_zero():
        hist_window.destroy()
        show_history(cond={"Status": 200})

    def show_success_one():
        hist_window.destroy()
        show_history(cond={"Status": 201})

    def show_success_four():
        hist_window.destroy()
        show_history(cond={"Status": 204})

    def show_sorted_status():
        hist_window.destroy()
        show_history(sort="Status")

    def show_sorted_url():
        hist_window.destroy()
        show_history(sort="URL")

    def show_sorted_method():
        hist_window.destroy()
        show_history(sort="Method")

    def del_hist():
        row = ent_fav_row.get()
        if row:
            clear_history(row)
            hist_window.destroy()
            show_history()

    def del_all_hist():
        clear_history()
        hist_window.destroy()

    def fav_hist():
        row = ent_fav_row.get()
        if row:
            update_fav(row)
            hist_window.destroy()
            show_history()

    def run_hist():
        row = ent_fav_row.get()
        if row:
            show_view(print_history_item(row))

    if cond:
        list_of_hist = print_history(full=True, cond=cond)
    elif sort:
        list_of_hist = print_history(full=True, sort=sort)
    else:
        list_of_hist = print_history(full=True)
    if list_of_hist:
        fav = print_history("Favourite", full=True)
        hist_window = tk.Tk()
        hist_window.title(f"History")

        menu = tk.Menu(hist_window)
        hist_window.config(menu=menu)
        menu.add_command(label="Show 200", font=font12i, command=show_success_zero)
        menu.add_command(label="Show 201", font=font12i, command=show_success_one)
        menu.add_command(label="Show 204", font=font12i, command=show_success_four)
        menu.add_command(label="Sort by status", font=font12i, command=show_sorted_status)
        menu.add_command(label="Sort by URL", font=font12i, command=show_sorted_url)
        menu.add_command(label="Sort by method", font=font12i, command=show_sorted_method)

        hist_frame = ScrollableFrame(hist_window)
        histrow = tk.IntVar(0)
        favrow = tk.IntVar(0)
        ent_hist = {}
        for dct in list_of_hist:
            y = yaml.safe_dump(dct, sort_keys=False)
            txt = tk.Text(hist_frame.scrollable_frame, height=6, width=35, wrap=tk.WORD, font=font12i)
            txt.insert(1.0, y)
            scroll = tk.Scrollbar(hist_frame.scrollable_frame, command=txt.yview)
            txt.config(yscrollcommand=scroll.set)

            if fav[favrow.get()]["Favourite"] == 'True':
                txt.config(bg="#cadaba")

            if favrow.get() % 2 == 0:
                txt.grid(row=histrow.get(), column=0, sticky="nsew")
                scroll.grid(row=histrow.get(), column=1, sticky="nsew")
            else:
                txt.grid(row=histrow.get(), column=2, sticky="nsew")
                scroll.grid(row=histrow.get(), column=3, sticky="nsew")
                histrow.set(histrow.get() + 1)
            favrow.set(favrow.get() + 1)
            ent_hist.update({dct.get("ID"): [txt, scroll]})
        hist_frame.grid(row=0, column=0, sticky="nsew")

        entry_frame = tk.Frame(hist_window, bd=1)
        fav_frame = tk.LabelFrame(entry_frame, bd=1, text="Make favorite by index", font=font12, labelanchor=tk.N)
        fav_button = tk.Button(fav_frame,
                           text="Favorite",
                           background="#cadaba",
                           foreground="#000",
                           padx=15,
                           pady=10,
                           width=11,
                           height=1,
                           compound="c",
                           font=font12i,
                           command=fav_hist)
        fav_button.grid(row=0, column=0, sticky="nsew")
        ent_fav_row = tk.Entry(fav_frame, width=6)
        ent_fav_row.grid(row=0, column=1, sticky="nsew")
        fav_frame.grid(row=1, column=0, sticky="nsew")

        run_frame = tk.LabelFrame(entry_frame, bd=1, text="Show selected", font=font12,
                              labelanchor=tk.N)
        run_button = tk.Button(run_frame,
                           text="Show",
                           background="#cadaba",
                           foreground="#000",
                           padx=15,
                           pady=10,
                           width=10,
                           height=1,
                           compound="c",
                           font=font12i,
                           command=run_hist)
        run_button.grid(row=0, column=0, sticky="nsew")
        run_frame.grid(row=1, column=1, sticky="nsew")

        del_frame = tk.LabelFrame(entry_frame, bd=1, text="Delete request with selected row", font=font12, labelanchor=tk.N)
        del_button = tk.Button(del_frame,
                           text="Delete selected",
                           background="#cadaba",
                           foreground="#000",
                           padx=15,
                           pady=10,
                           width=14,
                           height=1,
                           compound="c",
                           font=font12i,
                           command=del_hist)
        del_button.grid(row=0, column=0, sticky="nsew")
        del_all_button = tk.Button(del_frame,
                               text="Delete all",
                               background="#cadaba",
                               foreground="#000",
                               padx=15,
                               pady=10,
                               width=14,
                               height=1,
                               compound="c",
                               font=font12i,
                               command=del_all_hist)
        del_all_button.grid(row=0, column=1, sticky="nsew")
        del_frame.grid(row=1, column=2, sticky="nsew")
        entry_frame.grid(row=1, column=0, sticky="nsew")
    else:
        tk.messagebox.showinfo(
            "History is empty",
            "Send some requests to see them here")

def show_variables():
    def set_variables():
        res = {}
        for k, v in ent_var.items():
            if k and v and k.get() != '' and v.get() != '':
                res.update({k.get(): v.get()})
        with open("variables.yaml", 'w') as f:
            try:
                yaml.dump(res, f)
            except:
                return
        var_window.destroy()

    def add_var():
        e_key = tk.Entry(var_frame)
        e_key.grid(row=var_row.get(), column=0, sticky="nsew")
        e_val = tk.Entry(var_frame)
        e_val.grid(row=var_row.get(), column=1, sticky="nsew")
        ent_var.update({e_key: e_val})
        var_button.grid_remove()
        var_button.grid(row=var_row.get(), column=2, sticky="nsew")
        var_row.set(var_row.get() + 1)

    var_window = tk.Tk()
    var_window.title(f"Tree View")
    var_window.protocol("WM_DELETE_WINDOW", set_variables)
    var_frame = tk.LabelFrame(var_window, bd=1, text="Add or delete variables as key-value pairs", labelanchor=tk.N)
    var_row = tk.IntVar(0)
    ent_var = {}
    variables = get_variables()
    if variables:
        for k, v in variables.items():
            ent_key = tk.Entry(var_frame, width=20)
            ent_key.insert(0, k)
            ent_key.grid(row=var_row.get(), column=0, sticky="nsew")
            ent_val = tk.Entry(var_frame, width=50)
            ent_val.insert(0, v)
            ent_val.grid(row=var_row.get(), column=1, sticky="nsew")
            ent_var.update({ent_key: ent_val})
            var_row.set(var_row.get() + 1)
    ent_key = tk.Entry(var_frame, width=20)
    ent_key.grid(row=var_row.get(), column=0, sticky="nsew")
    ent_val = tk.Entry(var_frame, width=50)
    ent_val.grid(row=var_row.get(), column=1, sticky="nsew")
    ent_var.update({ent_key: ent_val})
    var_button = tk.Button(var_frame,
                            text="+Add",
                            background="#cadaba",
                            foreground="#000",
                            padx=15,
                            pady=10,
                            width=3,
                            height=1,
                            compound="c",
                            font=font12i,
                            command=add_var)
    var_button.grid(row=var_row.get(), column=2, sticky="nsew")
    var_row.set(var_row.get() + 1)
    var_frame.grid(row=0, column=0, sticky="nsew")

def add_param():
    e_key = tk.Entry(param_frame)
    e_key.grid(row=param_row.get(), column=0, sticky="nsew")
    e_val = tk.Entry(param_frame)
    e_val.grid(row=param_row.get(), column=1, sticky="nsew")
    ent_params.update({e_key: e_val})
    param_button.grid_remove()
    param_button.grid(row=param_row.get(), column=2, sticky="nsew")
    param_row.set(param_row.get() + 1)

def add_body():
    e_key = tk.Entry(body_frame)
    e_key.grid(row=body_row.get(), column=0, sticky="nsew")
    e_val = tk.Entry(body_frame)
    e_val.grid(row=body_row.get(), column=1, sticky="nsew")
    ent_body.update({e_key: e_val})
    body_button.grid_remove()
    body_button.grid(row=body_row.get(), column=2, sticky="nsew")
    body_row.set(body_row.get() + 1)

def add_header():
    e_key = tk.Entry(head_frame)
    e_key.grid(row=head_row.get(), column=0, sticky="nsew")
    e_val = tk.Entry(head_frame)
    e_val.grid(row=head_row.get(), column=1, sticky="nsew")
    ent_head.update({e_key: e_val})
    head_button.grid_remove()
    head_button.grid(row=head_row.get(), column=2, sticky="nsew")
    head_row.set(head_row.get() + 1)

def make_substr_var(vars, key):
    tmp = re.search(r"{@.+}", key)
    for k_var, v_var in vars.items():
        if k_var == tmp.group(0)[2:-1]:
            return re.sub(r"{@.+}", str(v_var), str(key))
    return key

def make_request():
    vars = get_variables()

    data = {}
    request = str()
    username = str()
    password = str()
    params = {}
    body = {}
    headers = {}
    if re.match(r".*{@.+}.*", ent_req.get()):
        request = make_substr_var(vars, ent_req.get())
    else:
        request = ent_req.get()
    for k, v in ent_params.items():
        if k and v and k.get() != '' and v.get() != '':
            key = k.get()
            val = v.get()
            if re.match(r".*{@.+}.*", key):
                key = make_substr_var(vars, key)
            if re.match(r".*{@.+}.*", val):
                val = make_substr_var(vars, val)
            params.update({key: val})
    for k, v in ent_body.items():
        if k and v and k.get() != '' and v.get() != '':
            key = k.get()
            val = v.get()
            if re.match(r".*{@.+}.*", key):
                key = make_substr_var(vars, key)
            if re.match(r".*{@.+}.*", val):
                val = make_substr_var(vars, val)
            body.update({key: val})
    for k, v in ent_head.items():
        if k and v and k.get() != '' and v.get() != '':
            key = k.get()
            val = v.get()
            if re.match(r".*{@.+}.*", key):
                key = make_substr_var(vars, key)
            if re.match(r".*{@.+}.*", val):
                val = make_substr_var(vars, val)
            headers.update({key: val})
    if re.match(r".*{@.+}.*", ent_username.get()):
        username = make_substr_var(vars, ent_username.get())
    else:
        username = ent_username.get()
    if re.match(r".*{@.+}.*", ent_password.get()):
        password = make_substr_var(vars, ent_password.get())
    else:
        password = ent_password.get()

    auth = {"username": username, "password": password}
    "Реквест отослали, получили респонз и заносим в базу"
    data.update({'Method': cur_method.get()})
    data.update({'URL': ent_req.get()})
    data.update({'Params': params})
    data.update({'Headers': headers})
    data.update({'Body': body})
    data.update({'Auth': auth})
    data.update({'Status': 200})
    data.update({'Response': {}})

    "Реквест отослали, получили респонз и заносим в базу + вызываем окошко"

    logger.log(cur_log.get(), f"Send {cur_method.get()} request to {ent_req.get()}")

    data = request_method(request, data)

    if data and data.get("Error"):
        tk.messagebox.showerror(
            "Request failed",
            data.get("Error"))
    elif data:
        hist = {}
        hist.update({'Method': cur_method.get()})
        hist.update({'URL': ent_req.get()})
        hist.update({'Params': params})
        hist.update({'Headers': headers})
        hist.update({'Body': body})
        hist.update({'Auth': auth})
        hist.update({'Status': data.get("Status")})
        hist.update({'Response': data.get("Response")})

        logger.log(cur_log.get(), f"Take {cur_method.get()} response from "
                                    f"{ent_req.get()} with status {data.get('Status')} in {data.get('Time')} seconds")
        if data.get('Status') < 400:
            logger.log(cur_log.get(), f"Send new record in db with successful status {data.get('Status')}")
            init_history(hist)

        show_view(data)

def cli_mode():
    vars = get_variables()
    data = {}
    request = str()
    username = str()
    password = str()
    params = {}
    body = {}
    head = {}

    if pars_args.params:
        for item in pars_args.params:
            if re.match(r"^.+=.+$", item):
                params.update({item.split('=')[0]: item.split('=')[1]})
    if pars_args.headers:
        for item in pars_args.headers:
            if re.match(r"^.+=.+$", item):
                head.update({item.split('=')[0]: item.split('=')[1]})
    if pars_args.body:
        for item in pars_args.body:
            if re.match(r"^.+=.+$", item):
                body.update({item.split('=')[0]: item.split('=')[1]})
    auth = {}
    if pars_args.auth:
        auth = {"username": pars_args.auth[0], "password": pars_args.auth[1]}
    else:
        auth = {"username": "", "password": ""}
    endpoint = str()
    if pars_args.endpoint:
        endpoint = pars_args.endpoint
    else:
        endpoint = ''
    method = str()
    if pars_args.method:
        method = pars_args.method
    else:
        method = 'GET'
    log = str()
    if pars_args.log:
        log = pars_args.log
    else:
        log = 'DEBUG'
    view = str()
    if pars_args.tree:
        view = "Tree"
    if pars_args.raw:
        view = "Raw"
    if pars_args.pretty:
        view = "Pretty"
    if pars_args.yaml:
        view = "Yaml"

    p = {}
    h = {}
    b = {}

    if re.match(r".*{@.+}.*", endpoint):
        request = make_substr_var(vars, endpoint)
    else:
        request = endpoint
    for key, val in params.items():
        if re.match(r".*{@.+}.*", key):
            key = make_substr_var(vars, key)
        if re.match(r".*{@.+}.*", val):
            val = make_substr_var(vars, val)
        p.update({key: val})
    for key, val in body.items():
        if re.match(r".*{@.+}.*", key):
            key = make_substr_var(vars, key)
        if re.match(r".*{@.+}.*", val):
            val = make_substr_var(vars, val)
        b.update({key: val})
    for key, val in head.items():
        if re.match(r".*{@.+}.*", key):
            key = make_substr_var(vars, key)
        if re.match(r".*{@.+}.*", val):
            val = make_substr_var(vars, val)
        h.update({key: val})
    if re.match(r".*{@.+}.*", auth.get("username")):
        auth.update({"username": make_substr_var(vars, auth.get("username"))})
    if re.match(r".*{@.+}.*", auth.get("password")):
        auth.update({"password": make_substr_var(vars, auth.get("password"))})


    data.update({'Method': method})
    data.update({'URL': endpoint})
    data.update({'Params': p})
    data.update({'Headers': h})
    data.update({'Body': b})
    data.update({'Auth': auth})


    if pars_args.history:
        list_of_hist = print_history(full=True)
        if pars_args.history == 'show' and list_of_hist:
            delim = '=' * 4 + '  ' + '=' * 6 + '  ' + '=' * 24 + '  ' + '=' * 30 + '  ' + '=' * 7
            print("---Request history---")
            print(delim)
            print("{:<4}  {:<6}  {:<24}  {:<30}  {:<7}"
                  .format('..', 'Method', 'URL', 'Params and request body', ' Status'))
            print(delim)
            for dct in list_of_hist:
                k = dct.get("ID")
                m = dct.get("Method")
                u = dct.get("URL")
                p = list(dct.get("Params").items())
                r = list(dct.get("Body").items())
                s = dct.get("Status")
                print("{:<4}  {:<6}  {:<24}  ".format(k, m, u[:24]), end='')
                if p:
                    for i in range(len(p)):
                        if i > 0:
                            print(' ' * 40, end='')
                        if i == 0:
                            print("{:<30}      {:<3}".format("Params= " + p[i][0][:10] + ': ' + p[i][1][:10], s))
                        else:
                            print(str(p[i][0] + ': ' + p[i][1])[:30])
                if r:
                    for i in range(len(r)):
                        if i > 0:
                            print(' ' * 40, end='')
                        if i == 0 and not p:
                            print("{:<30}      {:<3}".format("Body= " + r[i][0][:11] + ': ' + r[i][1][:11], s))
                        elif i == 0:
                            print(' ' * 40, end='')
                            print(str("Body= " + r[i][0] + ': ' + r[i][1])[:30])
                        else:
                            print(str(r[i][0] + ': ' + r[i][1])[:30])
                if not p and not r and s:
                    print("{:<30}      {:<3}".format('', s))
            print(delim)
            row = input('Enter request index to view full info, or "q" to quit: ')
            if row == 'q':
                exit()

            data = print_history_item(int(row))
            print(f"---Request {row}---")
            delim = '=' * 20 + '  ' + '=' * 57
            print(delim)
            print("{:<20}  {:<57}".format('..', 'Request info'))
            print(delim)
            print("{:<20}  {:<57}".format('Method', data.get('Method')))
            print("{:<20}  {:<57}".format('URL', str(data.get('URL'))[:57]))
            p = list(data.get("Params").items())
            h = list(data.get("Headers").items())
            r = list(data.get("Body").items())
            a = list(data.get("Auth").items())
            s = data.get("Status")
            if p:
                for i in range(len(p)):
                    if i > 0:
                        print(' ' * 22, end='')
                    if i == 0:
                        print("{:<20}  {:<57}".format("Params", p[i][0][:20] + ': ' + p[i][1][:35]))
                    else:
                        print(str(p[i][0] + ': ' + p[i][1])[:57])
            else:
                print("Params")
            if h:
                for i in range(len(h)):
                    if i > 0:
                        print(' ' * 22, end='')
                    if i == 0:
                        print("{:<20}  {:<57}".format("Headers", h[i][0][:20] + ': ' + h[i][1][:35]))
                    else:
                        print(str(h[i][0] + ': ' + h[i][1])[:57])
            else:
                print("Headers")
            if r:
                for i in range(len(r)):
                    if i > 0:
                        print(' ' * 22, end='')
                    if i == 0:
                        print("{:<20}  {:<57}".format("Request body", r[i][0][:20] + ': ' + r[i][1][:35]))
                    else:
                        print(str(r[i][0] + ': ' + r[i][1])[:57])
            else:
                print("Request body")
            if a:
                for i in range(len(a)):
                    if i > 0:
                        print(' ' * 22, end='')
                    if i == 0:
                        print("{:<20}  {:<57}".format("Basic Authentication", a[i][0][:20] + ': ' + a[i][1][:35]))
                    else:
                        print(str(a[i][0] + ': ' + a[i][1])[:57])
            else:
                print("Request body")
            print("{:<20}  {:<57}".format("Status", s))
            print(delim)
            print("---Response---")
            if pars_args.yaml:
                print(yaml.safe_dump(data.get("Response"), sort_keys=False))
            elif pars_args.pretty:
                print(json.dumps(data.get("Response"), indent=4))
            else:
                print(data.get("Response"))
        if pars_args.history == 'show' and not list_of_hist:
            print("---Send some requests to see them in history, now it`s empty---")
        if pars_args.history == 'clear':
            print("---Request history cleared---")
            clear_history()
    else:
        log = logging.INFO
        if pars_args.log == "warning":
            log = logging.WARNING
        if pars_args.log == "debug":
            log = logging.DEBUG

        logger.log(log, f"Send {data.get('Method')} request to {data.get('URL')}")

        data = request_method(request, data)

        if data and data.get("Error"):
            print("---Request failed, check input information or read HELP---")
            print(data.get("Error"))
        elif data:
            hist = {}
            hist.update({'Method': data.get("Method")})
            hist.update({'URL': data.get("URL")})
            hist.update({'Params': data.get("Params")})
            hist.update({'Headers': data.get("Headers")})
            hist.update({'Body': data.get("Body")})
            hist.update({'Auth': data.get("Auth")})
            hist.update({'Status': data.get("Status")})
            hist.update({'Response': data.get("Response")})

            status = "OK"
            if data.get('Status') > 400:
                status = "Not OK"

            print(f"--Got response {data.get('Status')} {status} in {data.get('Time')} seconds---")
            print("---Response body---")

            if pars_args.yaml:
                print(yaml.safe_dump(data.get("Response"), sort_keys=False))
            elif pars_args.pretty:
                print(json.dumps(data.get("Response"), indent=4))
            else:
                print(data.get("Response"))

            logger.log(log, f"Take {data.get('Method')} response from "
                        f"{data.get('URL')} with status {data.get('Status')} in {data.get('Time')} seconds")
            if data.get('Status') < 400:
                logger.log(log, f"Send new record in db with successful status {data.get('Status')}")
                init_history(hist)


def set_dicts():
    if pars_args.params:
        for item in pars_args.params:
            if re.match(r"^.+=.+$", item):
                params.update({item.split('=')[0]: item.split('=')[1]})
    if pars_args.headers:
        for item in pars_args.headers:
            if re.match(r"^.+=.+$", item):
                headers.update({item.split('=')[0]: item.split('=')[1]})
    if pars_args.body:
        for item in pars_args.body:
            if re.match(r"^.+=.+$", item):
                body.update({item.split('=')[0]: item.split('=')[1]})
    if pars_args.auth:
        username.set(pars_args.auth[0])
        password.set(pars_args.auth[1])
    if pars_args.endpoint:
        request.set(pars_args.endpoint)
    if pars_args.method:
        cur_method.set(pars_args.method)
    if pars_args.log:
        cur_log.set(pars_args.log)
    if pars_args.tree:
        cur_view.set(0)
    if pars_args.raw:
        cur_view.set(1)
    if pars_args.pretty:
        cur_view.set(2)
    if pars_args.yaml:
        cur_view.set(3)


if __name__ == '__main__':
    "Создание парсера входящих аргументов"
    parser = argparse.ArgumentParser(description='Endgame - Parser of HTML requests')
    parser.add_argument(
        '-g', '--gui',
        action='store_true',
        help='Activate GUI mode'
    )
    parser.add_argument(
        '--history',
        choices=['show', 'clear'],
        help='Show 10 last requests or clear all'
    )
    parser.add_argument(
        '-a', '--auth',
        nargs=2,
        type=str,
        help='Set username and password'
    )
    parser.add_argument(
        '-l', '--log',
        choices=['debug', 'info', 'warning'],
        help='Set logging level'
    )
    parser.add_argument(
        '-m', '--method',
        choices=['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
        help='Set request method'
    )
    parser.add_argument(
        '-e', '--endpoint',
        type=str,
        help='Set endpoint of request'
    )
    parser.add_argument(
        '-p', '--params',
        nargs='+',
        type=str,
        help='Set params of request'
    )
    parser.add_argument(
        '--headers',
        nargs='+',
        type=str,
        help='Set headers of request'
    )
    parser.add_argument(
        '-b', '--body',
        nargs='+',
        type=str,
        help='Set body of request'
    )
    parser.add_argument(
        '--tree',
        action='store_true',
        help='Set Tree view mode'
    )
    parser.add_argument(
        '-r', '--raw',
        action='store_true',
        help='Set Raw view mode'
    )
    parser.add_argument(
        '--pretty',
        action='store_true',
        help='Set Pretty view mode'
    )
    parser.add_argument(
        '-y', '--yaml',
        action='store_true',
        help='Set Yaml view mode'
    )
    pars_args = parser.parse_args()

    if len(sys.argv) == 1:
        parser.print_usage()
        exit()


    if not pars_args.gui:
        "Старт терминального режима"
        cli_mode()
        exit()


    "Главное окно и глобальные переменные"
    window = tk.Tk()
    window.title("Web json scraper")

    username = tk.StringVar()
    password = tk.StringVar()
    cur_method = tk.StringVar()
    cur_view = tk.IntVar()
    cur_log = tk.IntVar()
    request = tk.StringVar()


    "Ключи=значения из парсера в словари, перезаписываеться после SEND"
    params = {}
    body = {}
    headers = {}
    set_dicts()

    "Дальше только графическая часть если есть флаг -g/--gui"
    font12 = ("Times New Roman", 12, "normal")
    font12i = ("Times New Roman", 12, "italic")
    font16 = ("Times New Roman", 16, "italic")


    main_frame = tk.Frame(window, bd=5)
    mainmenu = tk.Menu(window)
    window.config(menu=mainmenu)

    log_menu = tk.Menu(mainmenu, tearoff=0)
    log_menu.add_command(label="Debug set", font=font12i, command=set_log_debug)
    log_menu.add_command(label="Info set", font=font12i, command=set_log_info)
    log_menu.add_command(label="Warning set", font=font12i, command=set_log_warn)
    mainmenu.add_cascade(label="Logging level", font=font12i, menu=log_menu)

    mainmenu.add_command(label="Variables", font=font12i, command=show_variables)

    mainmenu.add_command(label="History", font=font12i, command=show_history)

    mainmenu.add_command(label="Help", font=font12i, command=show_help)


    ent_frame = tk.LabelFrame(main_frame, bd=2, text="Choose method and send your request",
                              font=font12, labelanchor=tk.N)
    ent_subframe = tk.Frame(ent_frame, bd=5)
    combostyle = ttk.Style()
    combostyle.theme_create('combostyle', parent='alt',
                            settings={'TCombobox':
                                          {'configure':
                                               {'selectforeground': '#000',
                                                'selectbackground': '#cadaba',
                                                'fieldbackground': '#cadaba',
                                                'background': '#848482'
                                                }}}
                            )
    combostyle.theme_use('combostyle')

    cbox_req = ttk.Combobox(ent_subframe,
                            values=[
                                    "GET",
                                    "POST",
                                    "PUT",
                                    "PATCH",
                                    "DELETE"],
                            state="readonly",
                            font=font16,
                            width=7,
                            textvariable=cur_method,
                            background="#cadaba")
    if not cur_method.get() or cur_method.get() == 'GET':
        cbox_req.current(0)
    if cur_method.get() == 'POST':
        cbox_req.current(1)
    if cur_method.get() == 'PUT':
        cbox_req.current(2)
    if cur_method.get() == 'PATCH':
        cbox_req.current(3)
    if cur_method.get() == 'DELETE':
        cbox_req.current(4)
    cbox_req.grid(row=0, column=0, sticky="nsew")

    ent_req = tk.Entry(ent_subframe, textvariable=request, width=50)
    ent_req.grid(row=0, column=1, sticky="nsew", padx=5, pady=5)
    ent_button = tk.Button(ent_subframe,
                       text="Send",
                       background="#cadaba",
                       foreground="#000",
                       padx=15,
                       pady=10,
                       width=5,
                       font=font16,
                       command=make_request)
    ent_button.grid(row=0, column=2, sticky="nsew")
    ent_subframe.grid(row=0, column=0, sticky="nsew")
    ent_frame.grid(row=0, column=0, sticky="n")


    auth_frame = tk.LabelFrame(main_frame, bd=2, text="Basic Authentication", font=font12, labelanchor=tk.N)
    name_label = tk.Label(auth_frame, text="Enter username:", font=font12).grid(row=0, column=0, sticky="nsew")
    pass_label = tk.Label(auth_frame, text="Enter password:", font=font12).grid(row=0, column=1, sticky="nsew")
    ent_username = tk.Entry(auth_frame, textvariable=username, width=20)
    ent_username.grid(row=1, column=0, sticky="nsew")
    ent_password = tk.Entry(auth_frame, textvariable=password, width=50)
    ent_password.grid(row=1, column=1, sticky="nsew")
    auth_frame.grid(row=1, column=0, sticky="nsew")


    param_frame = tk.LabelFrame(main_frame, bd=1, text="Add query parameters as key-value pairs", labelanchor=tk.N)
    param_row = tk.IntVar(0)
    ent_params = {}
    for k, v in params.items():
        ent_key = tk.Entry(param_frame, width=20)
        ent_key.insert(0, k)
        ent_key.grid(row=param_row.get(), column=0, sticky="nsew")
        ent_val = tk.Entry(param_frame, width=50)
        ent_val.insert(0, v)
        ent_val.grid(row=param_row.get(), column=1, sticky="nsew")
        ent_params.update({ent_key: ent_val})
        param_row.set(param_row.get() + 1)
    ent_key = tk.Entry(param_frame, width=20)
    ent_key.grid(row=param_row.get(), column=0, sticky="nsew")
    ent_val = tk.Entry(param_frame, width=50)
    ent_val.grid(row=param_row.get(), column=1, sticky="nsew")
    ent_params.update({ent_key: ent_val})
    pixelVirtual = tk.PhotoImage(width=1, height=1)
    param_button = tk.Button(param_frame,
                           text="+Add",
                           background="#cadaba",
                           foreground="#000",
                           image=pixelVirtual,
                           padx=15,
                           pady=10,
                           width=22,
                           height=2,
                           compound="c",
                           font=font12i,
                           command=add_param)
    param_button.grid(row=param_row.get(), column=2, sticky="nsew")
    param_row.set(param_row.get() + 1)
    param_frame.grid(row=2, column=0, sticky="nsew")


    body_frame = tk.LabelFrame(main_frame, bd=1, text="Add request body as key-value pairs", labelanchor=tk.N)
    body_row = tk.IntVar(0)
    ent_body = {}
    for k, v in body.items():
        ent_key = tk.Entry(body_frame, width=20)
        ent_key.insert(0, k)
        ent_key.grid(row=body_row.get(), column=0, sticky="nsew")
        ent_val = tk.Entry(body_frame, width=50)
        ent_val.insert(0, v)
        ent_val.grid(row=body_row.get(), column=1, sticky="nsew")
        ent_body.update({ent_key: ent_val})
        body_row.set(body_row.get() + 1)
    ent_key = tk.Entry(body_frame, width=20)
    ent_key.grid(row=body_row.get(), column=0, sticky="nsew")
    ent_val = tk.Entry(body_frame, width=50)
    ent_val.grid(row=body_row.get(), column=1, sticky="nsew")
    ent_body.update({ent_key: ent_val})
    body_button = tk.Button(body_frame,
                             text="+Add",
                             background="#cadaba",
                             foreground="#000",
                             image=pixelVirtual,
                             padx=15,
                             pady=10,
                             width=22,
                             height=2,
                             compound="c",
                             font=font12i,
                             command=add_body)
    body_button.grid(row=body_row.get(), column=2, sticky="nsew")
    body_row.set(param_row.get() + 1)
    body_frame.grid(row=3, column=0, sticky="nsew")

    head_frame = tk.LabelFrame(main_frame, bd=1, text="Add request headers as key-value pairs", labelanchor=tk.N)
    head_row = tk.IntVar(0)
    ent_head = {}
    for k, v in headers.items():
        ent_key = tk.Entry(head_frame, width=20)
        ent_key.insert(0, k)
        ent_key.grid(row=head_row.get(), column=0, sticky="nsew")
        ent_val = tk.Entry(head_frame, width=50)
        ent_val.insert(0, v)
        ent_val.grid(row=head_row.get(), column=1, sticky="nsew")
        ent_head.update({ent_key: ent_val})
        head_row.set(head_row.get() + 1)
    ent_key = tk.Entry(head_frame, width=20)
    ent_key.grid(row=head_row.get(), column=0, sticky="nsew")
    ent_val = tk.Entry(head_frame, width=50)
    ent_val.grid(row=head_row.get(), column=1, sticky="nsew")
    ent_head.update({ent_key: ent_val})
    head_button = tk.Button(head_frame,
                            text="+Add",
                            background="#cadaba",
                            foreground="#000",
                            image=pixelVirtual,
                            padx=15,
                            pady=10,
                            width=22,
                            height=2,
                            compound="c",
                            font=font12i,
                            command=add_header)
    head_button.grid(row=head_row.get(), column=2, sticky="nsew")
    head_row.set(head_row.get() + 1)
    head_frame.grid(row=4, column=0, sticky="nsew")


    "Список тип\функция окон визуализации, можно расширять"
    views = [("Tree View", 0), ("Raw View", 1), ("Pretty View", 2), ("Yaml View", 3)]
    view_frame = tk.LabelFrame(main_frame, bd=2, text="Choose view mode", font=font12, labelanchor=tk.N)
    column = 0
    for txt, val in views:
        tk.Radiobutton(view_frame,
                       text=txt,
                       value=val,
                       variable=cur_view,
                       background="#cadaba",
                       foreground="#000",
                       padx=15,
                       pady=10,
                       width=12,
                       font=font12i,
                       command=set_view) \
            .grid(row=0, column=column, sticky="nsew")
        column += 1
    view_frame.grid(row=5, column=0, sticky="nsew")


    main_frame.grid(row=0, column=0, sticky="nsew")


    if pars_args.history:
        if pars_args.history == 'show':
            show_history()
        if pars_args.history == 'clear':
            clear_history()
    cur_log.set(20)
    window.mainloop()
