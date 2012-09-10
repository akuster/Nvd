import sys
import os
import glob
import Constants

cveweb = Constants.cveweb
data_dir = os.path.join(cveweb,"data")
tmp_dir = Constants.cvetmpdata

def format_ref(filename):
    return ('<a href="/data/'+filename+'">'+filename[:-5]+'</a>')

def create_index_page(filename, name, search_string, header, footer):
    mode = 'w'

    if os.path.isfile(filename):
        mode = 'a'

    try:
        fd = open(filename, "w")
    except IOError:
        print "Cannot open main index file (filename)"
        raise

    msg = header
    msg += "<table>\n"
    msg += "<tr>\n"
    msg += "<td> "
    a = 0

    if mode == 'a':
        indexs = glob.glob(os.path.join(tmp_dir, search_string))
        for index in indexs:
            if os.path.basename(index) == name:
                continue
            msg += format_ref(os.path.basename(index))
            msg += "</td>"
            a += 1
            if a == 4:
                msg += "</tr>\n"
                msg += "<tr>\n"
                a = 0
            msg += "<td> "
    
    msg += format_ref(os.path.basename(name))
    msg += "</td></tr>\n"
    msg += "</table>\n"
    msg += "</body>\n"
    msg += footer
    msg += "</html>\n"
    
    try:
        fd.write(msg)
    except:
        print "Cannot write to file (filename)"
        raise

    fd.close()
    return

def create_cve_index(cve):

    if not os.path.isdir(tmp_dir):
        os.makedirs(tmp_dir)

    try:
        prefix, year, index = cve.split("-")
    except:
        raise

    name = "cve-"+year+".html"
    filename = os.path.join(tmp_dir,"include-cve-index.html")
    header = "<br><center><h1>CVE index</h1></center><hr />\n"
    footer = ""
    create_index_page(filename, name, "cve-*.html", header, footer)

# This assumes $filename is unique.
def create_cve_year_index(cve):
    mode = 'w'
    lstmode = 'w'

    try:
        prefix, year, index = cve.split("-")
    except:
        raise

    yr_index = "cve-"+year
    name = 'CVE-' + year + "-"+index
    filename = os.path.join(tmp_dir,yr_index+".html")
    lstname = os.path.join(tmp_dir,yr_index+".lst")

    if os.path.isfile(filename):
        mode = 'a'

    try:
        fd = open(filename, "w")
    except IOError:
        print "Cannot open main index file (filename)"
        raise

    if os.path.isfile(lstname):
        lstmode = 'a'
        try:
            fdlst = open(lstname, 'r')
        except IOError:
            print "Cannot open main index file (lstname)"
            raise
        
        indexs = fdlst.readlines()
        fdlst.close()

    fdlst = open(lstname, 'w')

    header = "<br><br><center><h1>"
    header += year+" CVE index</h1></center><hr />\n"

    footer = "<footer>"
    footer += "<hr />"
    footer += "<center>"
    footer += '<a href="../index.html">Home</a>'
    footer += "</center>"
    footer += "</footer>"

    msg = header
    msg += "<table>\n"
    msg += "<tr>\n"
    msg += "<td> "
    a = 0

    if mode == 'a' and lstmode == 'a':
        for index in indexs:
            oldName = index.strip('\n')
            msg += '<a href="/cgi-bin/form.py?cve=%s">%s</a>' % (oldName, oldName)
            fdlst.write(oldName+'\n')
            msg += "</td>"
            a += 1
            if a == 4:
                msg += "</tr>\n"
                msg += "<tr>\n"
                a = 0
            msg += "<td> "

    msg += '<a href="/cgi-bin/form.py?cve=%s">%s</a>' % (name, name)
    msg += "</td></tr>\n"
    msg += "</table>\n"
    msg += "</body>\n"
    msg += footer
    msg += "</html>\n"
    
    try:
        fd.write(msg)
    except:
        print "Cannot write to file (filename)"
        raise

    fdlst.write(name) 

    fdlst.close()
    fd.close()
    return

def create_cve_page(cve):
    try:
        prefix, year, seq = cve.split("-")
    except:
        raise

    name = "CVE-"+ year +"-"+ seq +".html"
    filename = os.path.join(tmp_dir,name)

    if os.path.isfile(filename):
        return False

    try:
        fd = open(filename, 'w')
    except:
        raise

    msg = "<html>\n"
    msg += "<body>\n"

    msg += "<h1>"
    msg += name[:-5]
    msg += "</h1>\n"
    msg += "<h2>Common Vulnerabilities and Exposures</h2>\n"
    msg += "<hr/>\n"
    msg += '<a href = "http://cve.mitre.org/cgi-bin/cvename.cgi?name='
    msg += cve
    msg += '">'
    msg += cve
    msg += " at Mitre</a><br />\n"
    msg += "<h3>MontaVista information </h3><hr />\n"
    msg += "<!-- *** MV CVE DATA *** -->\n"    
    msg += "</table>\n"
    msg += "</body>\n"
    msg += "<hr /><footer><center>"
    msg += '<td><a href="'
    msg += "cve-"+ year +".html"
    msg += '">[Index]</a></td>'
    msg += '<td><a href="../form.php?cve='+ name[:-5] +'">Edit</a></td>'
    msg += "</center></footer>"
    msg += "</html>\n"
    
    try:
        fd.write(msg)
    except:
        print "Cannot write to file (filename)"
        raise

    fd.close()
    return

def webify_cve(cve):
    create_cve_index(cve)
    create_cve_year_index(cve)


def test(args):
    webify_cve(args[1])

if __name__ == "__main__":
    sys.exit(test(sys.argv))

