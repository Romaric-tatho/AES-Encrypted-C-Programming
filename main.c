#include<stdio.h>
#include<stdlib.h>
#include<gtk/gtk.h>

int main(int argc ,char **argv)
{
    gtk_init(&argc , &argv);
    GtkWidget *win;
    win=gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_default_size(GTK_WINDOW(win),800,500);
    gtk_window_set_position(GTK_WINDOW(win),GTK_WIN_POS_CENTER);
    gtk_window_set_title(GTK_WINDOW(win),"AES CRYPTAGE");
    g_signal_connect(G_OBJECT(win),"delete-event",G_CALLBACK(gtk_main_quit),NULL);
    gtk_widget_show(win);
    gtk_main();
    return 0;
}