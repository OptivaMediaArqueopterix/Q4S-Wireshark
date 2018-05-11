/* editor_file_dialog.h
 *
 * File dialog that can be used as an "inline editor" in a table
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef EDITOR_FILE_DIALOG_H_
#define EDITOR_FILE_DIALOG_H_

#include <QFileDialog>
#include <QModelIndex>

class EditorFileDialog : public QFileDialog
{
    Q_OBJECT
public:
    explicit EditorFileDialog(const QModelIndex& index, QWidget* parent, Qt::WindowFlags flags);
    explicit EditorFileDialog(const QModelIndex& index, QWidget* parent = 0, const QString & caption = QString(), const QString & directory = QString(), const QString & filter = QString());

    void accept();

signals:
    void acceptEdit(const QModelIndex& index);

protected:
    const QModelIndex index_; //saved index of table cell
};

#endif /* EDITOR_FILE_DIALOG_H_ */

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
