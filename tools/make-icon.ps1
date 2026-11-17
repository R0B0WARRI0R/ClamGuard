param(
    [string]$OutFile = "$PSScriptRoot\..\app.ico"
)

Add-Type -AssemblyName System.Drawing

function Add-IconPng([int]$size, $list) {
    $bmp = [System.Drawing.Bitmap]::new($size, $size)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
    $g.Clear([System.Drawing.Color]::Transparent)

    $pad = [Math]::Max(1, [int]($size * 0.035))
    $w = $size - 2 * $pad
    $h = $size - 2 * $pad
    $d = [Math]::Max(2, [int]($size * 0.42))

    $path = [System.Drawing.Drawing2D.GraphicsPath]::new()
    $path.AddArc($pad, $pad, $d, $d, 180, 90)
    $path.AddArc($pad + $w - $d, $pad, $d, $d, 270, 90)
    $path.AddArc($pad + $w - $d, $pad + $h - $d, $d, $d, 0, 90)
    $path.AddArc($pad, $pad + $h - $d, $d, $d, 90, 90)
    $path.CloseFigure()

    $rect = [System.Drawing.Rectangle]::new($pad, $pad, $w, $h)
    $brush = [System.Drawing.Drawing2D.LinearGradientBrush]::new($rect,
        [System.Drawing.Color]::FromArgb(255, 59, 130, 246),
        [System.Drawing.Color]::FromArgb(255, 29, 78, 216), 90)
    $g.FillPath($brush, $path)

    $cx = $size / 2.0
    $left = $size * 0.30
    $right = $size * 0.70
    $top = $size * 0.24
    $mid = $size * 0.54
    $bottom = $size * 0.78
    $shoulder = $top + $size * 0.05
    $shield = [System.Drawing.PointF[]]@(
        [System.Drawing.PointF]::new($cx, $top),
        [System.Drawing.PointF]::new($right, $shoulder),
        [System.Drawing.PointF]::new($right, $mid),
        [System.Drawing.PointF]::new($cx, $bottom),
        [System.Drawing.PointF]::new($left, $mid),
        [System.Drawing.PointF]::new($left, $shoulder)
    )
    $white = [System.Drawing.SolidBrush]::new([System.Drawing.Color]::White)
    $g.FillPolygon($white, $shield)

    $penWidth = [Math]::Max(1.4, $size * 0.055)
    $pen = [System.Drawing.Pen]::new([System.Drawing.Color]::FromArgb(255, 29, 78, 216), $penWidth)
    $pen.StartCap = [System.Drawing.Drawing2D.LineCap]::Round
    $pen.EndCap = [System.Drawing.Drawing2D.LineCap]::Round
    $pen.LineJoin = [System.Drawing.Drawing2D.LineJoin]::Round
    $check = [System.Drawing.PointF[]]@(
        [System.Drawing.PointF]::new(($size * 0.385), ($size * 0.515)),
        [System.Drawing.PointF]::new(($size * 0.465), ($size * 0.605)),
        [System.Drawing.PointF]::new(($size * 0.635), ($size * 0.415))
    )
    $g.DrawLines($pen, $check)

    $rectBits = [System.Drawing.Rectangle]::new(0, 0, $size, $size)
    $locked = $bmp.LockBits($rectBits, [System.Drawing.Imaging.ImageLockMode]::ReadOnly,
        [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $stride = $locked.Stride
    $pixels = New-Object byte[] ($stride * $size)
    [System.Runtime.InteropServices.Marshal]::Copy($locked.Scan0, $pixels, 0, $pixels.Length)
    $bmp.UnlockBits($locked)

    $ms = [System.IO.MemoryStream]::new()
    $bw = [System.IO.BinaryWriter]::new($ms)
    $bw.Write([Int32]40)
    $bw.Write([Int32]$size)
    $bw.Write([Int32]($size * 2))
    $bw.Write([Int16]1)
    $bw.Write([Int16]32)
    $bw.Write([Int32]0)
    $bw.Write([Int32]($size * $size * 4))
    $bw.Write([Int32]0)
    $bw.Write([Int32]0)
    $bw.Write([Int32]0)
    $bw.Write([Int32]0)
    for ($y = $size - 1; $y -ge 0; $y--) {
        $bw.Write($pixels, $y * $stride, $size * 4)
    }
    $maskStride = [int]([Math]::Floor(($size + 31) / 32) * 4)
    $mask = New-Object byte[] ($maskStride * $size)
    $bw.Write($mask)
    $bw.Flush()
    $bytes = $ms.ToArray()
    $list.Add($bytes) | Out-Null

    $bw.Dispose()
    $ms.Dispose()
    $pen.Dispose()
    $white.Dispose()
    $brush.Dispose()
    $path.Dispose()
    $g.Dispose()
    $bmp.Dispose()
}

$sizes = @(16, 32, 48, 64, 256)
$images = [System.Collections.ArrayList]::new()
foreach ($s in $sizes) {
    Add-IconPng $s $images
}

$outPath = [System.IO.Path]::GetFullPath($OutFile)
$dir = [System.IO.Path]::GetDirectoryName($outPath)
if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }

$fs = [System.IO.FileStream]::new($outPath, [System.IO.FileMode]::Create)
$bw = [System.IO.BinaryWriter]::new($fs)
$bw.Write([UInt16]0)
$bw.Write([UInt16]1)
$bw.Write([UInt16]$sizes.Count)

$offset = 6 + 16 * $sizes.Count
for ($i = 0; $i -lt $sizes.Count; $i++) {
    $s = $sizes[$i]
    $data = [byte[]]$images[$i]
    $dim = if ($s -ge 256) { 0 } else { $s }
    $bw.Write([byte]$dim)
    $bw.Write([byte]$dim)
    $bw.Write([byte]0)
    $bw.Write([byte]0)
    $bw.Write([UInt16]1)
    $bw.Write([UInt16]32)
    $bw.Write([UInt32]$data.Length)
    $bw.Write([UInt32]$offset)
    $offset += $data.Length
}
for ($i = 0; $i -lt $sizes.Count; $i++) {
    $bw.Write([byte[]]$images[$i])
}
$bw.Flush()
$bw.Close()
$fs.Close()

Write-Host "Icono creado: $outPath"
