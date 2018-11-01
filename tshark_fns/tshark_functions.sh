# in a .bash_profile (or sourced, or ...)

# tshark_cols - add fields to the INFO line (aka _ws.col.Info)

# usage:
#   tshark_cols field [field [field ...]]

#   tshark -r capture.pcap $(tshark_cols nfs.fh.hash)
# expands to
#   tshark -r capture.pcap -z proto,colinfo,nfs.fh.hash,nfs.fh.hash
# and looks like:
# 43641   3.931346 10.119.184.55 → 10.116.232.30 NFS 226 V3 READDIRPLUS Call, FH: 0x518a9fd6  nfs.fh.hash == 0x518a9fd6
# 43644   3.964307 10.116.232.30 → 10.119.184.55 NFS 1514 V3 READDIRPLUS Reply (Call In 43641) . ..  nfs.fh.hash == 0x518a9fd6

tshark_cols() {
        while [[ -n $1 ]] ; do
                echo -n " -z proto,colinfo,$1,$1"
                shift
        done
}


# tshark_fields - display _ONLY_ these fields (and may only appear once on the command line)

# usage:
#   tshark_fields field [field [field ...]]

#   tshark -r capture.pcap $(tshark_fields frame.number) 'condition...'
# expands to
#   tshark -r capture.pcap -Tfields -E header=n -e frame.number 'condition...'
# and looks like:
# 43641
# 43644
# 43655
# ...
shark_fields() {
        echo -n " -Tfields -E header=y"
        while [[ -n $1 ]] ; do
                echo -n " -e $1"
                shift
        done
}


# tshark_any_of - select any of these values for the given field (used in a condition)
#
# usage:
#   tshark_any_of field value [value [value]]

# ex:
#   tshark -r capture.pcap "$(tshark_any_of nfs.procedure_v3 readdir readdirplus)"
# expands to
#   tshark -r capture.pcap "$(tshark_any_of nfs.procedure_v3 readdir readdirplus)"

# ex:
# for f in {1..5} ; do echo $f ; done >interesting_frames
#   tshark -r capture.pcap "$(tshark_any_of frame.number $(cat interesting_frames))"
# expands to
#   tshark -r capture.pcap "frame.number==1 || frame.number==2 || frame.number==3 || frame.number==4 || frame.number==5"

tshark_any_of() {
        ct=0
        [[ -z $1 ]] && return
        field=$1 ; shift
        if [[ $# -gt 0 ]] ; then
                while [[ -n $1 ]] ; do
                        [[ $ct -gt 0 ]] && echo -n " || "
                        echo -n "$field==$1" ; ct=$(($ct+1))
                        shift
                done
        else
                read args
                tshark_any_of $field $args
        fi
}
