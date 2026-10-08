# Custom NSIS include hook for KCP Proxy Client (electron-builder nsis.include).
#
# Besides the attribute below, the mere existence of this file matters:
# electron-builder only adds the build/ directory to the makensis include
# search path when a custom include is present, which is how
# installSection_details.nsh (referenced by installer.nsi) gets resolved.
#
# Show the details view on the INSTFILES page by default instead of hiding it
# behind the "Show details" button. Without this the re-enabled detail lines
# would still be invisible until the user clicks the button.
ShowInstDetails show
