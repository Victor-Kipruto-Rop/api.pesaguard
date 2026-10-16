from __future__ import annotations

import html


def escape_email_value(value: object) -> str:
    return html.escape(str(value if value is not None else ""), quote=True)


def render_branded_email(
    title: str,
    preheader: str,
    content: str,
    locale: str = "en",
    eyebrow: str = "PESAGUARD UPDATE",
) -> str:
    title_html = escape_email_value(title)
    preheader_html = escape_email_value(preheader)
    language = "sw" if locale == "sw" else "en"
    footer = (
        "Ujumbe wa kiotomatiki kutoka PesaGuard."
        if locale == "sw"
        else "An automated message from PesaGuard."
    )
    return f"""<!doctype html>
<html lang="{language}">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="color-scheme" content="light">
    <title>{title_html}</title>
</head>
<body style="margin:0;padding:0;background-color:#f2f5f3;color:#17231d;font-family:Arial,Helvetica,sans-serif;-webkit-text-size-adjust:100%;">
    <div style="display:none;max-height:0;overflow:hidden;opacity:0;color:transparent;mso-hide:all;">{preheader_html}</div>
    <table data-pesaguard-email-shell="1" role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="width:100%;background-color:#f2f5f3;">
        <tr>
            <td align="center" style="padding:32px 14px;">
                <table role="presentation" width="620" cellspacing="0" cellpadding="0" border="0" style="width:100%;max-width:620px;border-collapse:separate;border-spacing:0;">
                    <tr>
                        <td style="padding:25px 30px;background-color:#12372b;border-radius:18px 18px 0 0;">
                            <table role="presentation" cellspacing="0" cellpadding="0" border="0">
                                <tr>
                                    <td width="42" height="42" align="center" valign="middle" style="width:42px;height:42px;border-radius:13px;background-color:#2d7655;color:#ffffff;font-size:18px;font-weight:700;letter-spacing:-1px;">P</td>
                                    <td style="padding-left:12px;color:#ffffff;font-size:18px;font-weight:700;letter-spacing:.2px;">PesaGuard<br><span style="color:#c5d9ce;font-size:11px;font-weight:400;letter-spacing:1.4px;text-transform:uppercase;">Financial operations</span></td>
                                </tr>
                            </table>
                        </td>
                    </tr>
                    <tr>
                        <td style="padding:34px 30px 30px;background-color:#ffffff;border-left:1px solid #e4ebe6;border-right:1px solid #e4ebe6;">
                            <p style="margin:0 0 10px;color:#367856;font-size:11px;font-weight:700;letter-spacing:1.6px;text-transform:uppercase;">{escape_email_value(eyebrow)}</p>
                            <h1 style="margin:0;color:#17231d;font-size:26px;line-height:1.25;font-weight:700;letter-spacing:-.5px;">{title_html}</h1>
                            <div style="padding-top:22px;">{content}</div>
                        </td>
                    </tr>
                    <tr>
                        <td style="padding:19px 30px 23px;background-color:#f9fbf9;border:1px solid #e4ebe6;border-top:0;border-radius:0 0 18px 18px;">
                            <p style="margin:0;color:#627168;font-size:12px;line-height:1.6;">{escape_email_value(footer)}</p>
                            <p style="margin:7px 0 0;color:#87938b;font-size:11px;line-height:1.5;">PesaGuard &middot; Secure financial operations</p>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>"""
