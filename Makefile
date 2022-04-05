# vim: tabstop=8
PREFIX=		/usr/local
GIT_DESC!=	git describe --tags
VERSION=	${empty(GIT_DESC):?unknown:${GIT_DESC:S/^v//1}}
ARCH!=		pkg config abi | cut -d: -f 3
MAINTAINER=	richard9404@gmail.com
WWW=		https://github.com/cairijun/prometheus_opnsense_exporter

WORK_DIR=	work
STAGE_DIR=	${WORK_DIR}${PREFIX}

BIN=		bin/prometheus_opnsense_exporter
PKG_FILES!=	find pkg -type f
COPY_FILES=	${PKG_FILES:N*.in:S/^pkg\///g}
GEN_FILES=	${PKG_FILES:M*.in:R:S/^pkg\///g:N+MANIFEST}

LICENSE_DIR=	share/licenses/prometheus_opnsense_exporter-${VERSION}

GEN_FILE_VARS=	PREFIX VERSION ARCH MAINTAINER WWW
.for var in ${GEN_FILE_VARS}
GEN_FILE_SED_CMDS+="-e"
GEN_FILE_SED_CMDS+="s!%%${var}%%!${${var}:q}!g"
.endfor

${STAGE_DIR}/${BIN}: *.go go.mod go.sum
	go build -o ${.TARGET} -ldflags "-X main.pkgVersion=${VERSION}"

.for file in ${GEN_FILES}
${STAGE_DIR}/${file}: pkg/${file:S/$/.in/g}
	mkdir -p ${.TARGET:H}
	sed ${GEN_FILE_SED_CMDS} ${.ALLSRC} > ${.TARGET}
	chmod ${:!stat -f %Lp ${.ALLSRC}!} ${.TARGET}
.endfor

.for file in ${COPY_FILES}
${STAGE_DIR}/${file}: pkg/${file}
	mkdir -p ${.TARGET:H}
	cp -p ${.ALLSRC} ${.TARGET}
.endfor

${STAGE_DIR}/${LICENSE_DIR}/LICENSE: LICENSE
	mkdir -p ${.TARGET:H}
	cp -p ${.ALLSRC} ${.TARGET}

DIST_FILES=	\
	${STAGE_DIR}/${BIN} \
	${GEN_FILES:S/^/${STAGE_DIR}\//g} \
	${COPY_FILES:S/^/${STAGE_DIR}\//g} \
	${STAGE_DIR}/${LICENSE_DIR}/LICENSE

${WORK_DIR}/plist:
	rm -f ${.TARGET}
.for file in ${DIST_FILES}
	echo ${file:S/^${STAGE_DIR}\///g} >> ${.TARGET}
.endfor

${WORK_DIR}/+MANIFEST: pkg/+MANIFEST.in
	sed ${GEN_FILE_SED_CMDS} ${.ALLSRC} > ${.TARGET}

${WORK_DIR}/prometheus_opnsense_exporter-${VERSION}.pkg: ${DIST_FILES} ${WORK_DIR}/plist ${WORK_DIR}/+MANIFEST
	pkg create -o ${.TARGET:H} -r ${WORK_DIR} -m ${WORK_DIR} -p ${WORK_DIR}/plist -v

pkg: ${WORK_DIR}/prometheus_opnsense_exporter-${VERSION}.pkg

clean:
	rm -rf ${WORK_DIR}
