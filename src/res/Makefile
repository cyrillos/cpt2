obj-y		+= vdso-rhel5.o
obj-y		+= vdso-rhel6.o

vdso-5-size	:= $(shell stat -c%s $(obj)/vdso-rhel5.so)
vdso-6-size	:= $(shell stat -c%s $(obj)/vdso-rhel6.so)

$(obj)/vdso-rhel6.c: $(obj)/vdso-rhel6.so
	$(E) "  GEN     " $@
	$(Q) echo '/* Autogenerated */' > $@
	$(Q) echo 'const char vdso_blob_rhel6[$(vdso-6-size)] = {' >> $@
	$(Q) hexdump -v -e '"\t" 8/1 "0x%02x, " "\n"' $^ >> $@
	$(Q) echo '};' >> $@

$(obj)/vdso-rhel5.c: $(obj)/vdso-rhel5.so
	$(E) "  GEN     " $@
	$(Q) echo '/* Autogenerated */' > $@
	$(Q) echo 'const char vdso_blob_rhel5[$(vdso-5-size)] = {' >> $@
	$(Q) hexdump -v -e '"\t" 8/1 "0x%02x, " "\n"' $^ >> $@
	$(Q) echo '};' >> $@

$(obj)/vdso-rhel.h: $(obj)/vdso-rhel6.c $(obj)/vdso-rhel5.c
	$(E) "  GEN     " $@
	$(Q) echo '/* Autogenerated */' > $@
	$(Q) echo '#ifndef __CPT2_VDSO_RHEL_H__' >> $@
	$(Q) echo '#define __CPT2_VDSO_RHEL_H__' >> $@
	$(Q) echo 'extern const char vdso_blob_rhel6[$(vdso-6-size)];' >> $@
	$(Q) echo 'extern const char vdso_blob_rhel5[$(vdso-5-size)];' >> $@
	$(Q) echo '#endif /* __CPT2_VDSO_RHEL_H__ */' >> $@

$(obj)/built-in.o: | $(obj)/vdso-rhel.h

cleanup-y += $(obj)/vdso-rhel6.c
cleanup-y += $(obj)/vdso-rhel5.c
cleanup-y += $(obj)/vdso-rhel.h

ifneq ($(MAKECMDGOALS),clean)
incdeps := y
endif
